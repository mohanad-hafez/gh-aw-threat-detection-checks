package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type Step struct {
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
}
type Job struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Conclusion string  `json:"conclusion"`
	Log        *string `json:"log"`
	LogError   string  `json:"log_error"`
	Steps      []Step  `json:"steps"`
}
type Run struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Created    string `json:"created_at"`
	Updated    string `json:"updated_at"`
	Jobs       []Job  `json:"jobs"`
}
type Input struct {
	Now     string `json:"now"`
	ScanURL string `json:"scan_url"`
	Runs    []Run  `json:"runs"`
}
type Failure struct {
	Workflow   string `json:"workflow"`
	RunID      int64  `json:"run_id"`
	RunURL     string `json:"run_url"`
	JobID      int64  `json:"job_id"`
	JobURL     string `json:"job_url"`
	Conclusion string `json:"conclusion"`
	Kind       string `json:"failure_kind"`
	Reason     string `json:"reason"`
}
type Read struct {
	JobID int64 `json:"job_id"`
	Tail  int   `json:"tail_lines"`
}
type Output struct {
	Actions    []map[string]any `json:"actions"`
	Failures   []Failure        `json:"failures"`
	Reads      []Read           `json:"log_reads"`
	SoftChecks int              `json:"soft_checks"`
	Capped     bool             `json:"capped"`
}

func parse(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }
func hard(s string) bool       { return s == "failure" || s == "timed_out" || s == "action_required" }
func monitor(in Input) (Output, error) {
	out := Output{Actions: []map[string]any{}, Failures: []Failure{}, Reads: []Read{}}
	now := parse(in.Now)
	if now.IsZero() {
		return out, fmt.Errorf("invalid clock")
	}
	recent := func(s string) bool { t := parse(s); return !t.Before(now.Add(-24*time.Hour)) && !t.After(now) }
	runs := []Run{}
	for _, r := range in.Runs {
		if r.Status == "completed" && (recent(r.Created) || recent(r.Updated)) {
			runs = append(runs, r)
		}
	}
	sort.SliceStable(runs, func(i, j int) bool { return parse(runs[i].Created).After(parse(runs[j].Created)) })
	if len(runs) > 80 {
		runs = runs[:80]
	}
	seen := map[int64]bool{}
	for _, r := range runs {
		if r.Conclusion == "cancelled" || r.Conclusion == "skipped" || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		var job *Job
		for i := range r.Jobs {
			if r.Jobs[i].Name == "detection" {
				job = &r.Jobs[i]
				break
			}
		}
		if job == nil {
			continue
		}
		kind, reason := "", ""
		if hard(job.Conclusion) {
			kind, reason = "job", job.Conclusion
			for _, s := range job.Steps {
				if s.Conclusion == "failure" || s.Conclusion == "timed_out" {
					reason = s.Name
					break
				}
			}
		} else if job.Conclusion == "success" {
			if out.SoftChecks >= 30 {
				out.Capped = true
				continue
			}
			out.SoftChecks++
			out.Reads = append(out.Reads, Read{job.ID, 200})
			if job.LogError != "" {
				continue
			}
			if job.Log == nil {
				return out, fmt.Errorf("missing captured log for job %d", job.ID)
			}
			lines := strings.Split(strings.TrimRight(*job.Log, "\r\n"), "\n")
			if len(lines) > 200 {
				lines = lines[len(lines)-200:]
			}
			tail := strings.Join(lines, "\n")
			for _, m := range []string{"threat-detect binary not found on PATH", "reason=agent_failure", "reason=parse_error"} {
				if strings.Contains(tail, m) {
					reason = m
					break
				}
			}
			if reason == "" {
				continue
			}
			kind = "step"
		} else {
			continue
		}
		url := fmt.Sprintf("https://github.com/github/gh-aw/actions/runs/%d", r.ID)
		out.Failures = append(out.Failures, Failure{r.Name, r.ID, url, job.ID, fmt.Sprintf("%s/job/%d", url, job.ID), job.Conclusion, kind, reason})
	}
	if len(out.Failures) > 0 {
		count := 0
		bullets := []string{}
		for _, f := range out.Failures {
			if f.Kind == "job" {
				count++
			}
			bullets = append(bullets, fmt.Sprintf("- %s — run %s — job %s — %s — %s — %s", f.Workflow, f.RunURL, f.JobURL, f.Conclusion, f.Kind, f.Reason))
		}
		summary := fmt.Sprintf("%d failing detection jobs (%d hard, %d soft) in the last 24 hours.", len(out.Failures), count, len(out.Failures)-count)
		if out.Capped {
			summary += " Soft-failure checks capped at 30 jobs."
		}
		encoded, _ := json.MarshalIndent(out.Failures, "", "  ")
		body := summary + "\n\n## Failing Detection Jobs\n\n" + strings.Join(bullets, "\n") + "\n\n```json\n" + string(encoded) + "\n```\n\nScanned: " + in.ScanURL
		out.Actions = append(out.Actions, map[string]any{"kind": "create_issue", "title": "Detection failures in github/gh-aw - " + now.Format("2006-01-02"), "labels": []string{"automation", "detection-monitor"}, "body": body})
	}
	return out, nil
}
func main() {
	if len(os.Args) == 3 && os.Args[1] == "--input" {
		raw, err := os.ReadFile(os.Args[2])
		if err != nil {
			panic(err)
		}
		var in Input
		if err = json.Unmarshal(raw, &in); err != nil {
			panic(err)
		}
		out, err := monitor(in)
		if err != nil {
			panic(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
			panic(err)
		}
		return
	}
	if len(os.Args) != 3 {
		panic("usage: check CASES OUTPUT or check --input INPUT")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var suite struct {
		ID    string `json:"id"`
		Cases []struct {
			ID        string `json:"id"`
			Partition string `json:"partition"`
			Input     Input  `json:"input"`
			Expected  struct {
				Count  int      `json:"action_count"`
				Kinds  []string `json:"failure_kinds"`
				Reads  int      `json:"log_read_count"`
				Capped *bool    `json:"capped"`
				Reason string   `json:"reason"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &suite); err != nil {
		panic(err)
	}
	results := []map[string]any{}
	passed := 0
	for _, c := range suite.Cases {
		start := time.Now()
		out, e := monitor(c.Input)
		message := ""
		if e != nil {
			message = e.Error()
		}
		if len(out.Actions) != c.Expected.Count || len(out.Failures) != len(c.Expected.Kinds) || len(out.Reads) != c.Expected.Reads {
			message = "count mismatch"
		}
		for i, f := range out.Failures {
			if i >= len(c.Expected.Kinds) || f.Kind != c.Expected.Kinds[i] {
				message = "failure kind mismatch"
			}
		}
		if c.Expected.Capped != nil && out.Capped != *c.Expected.Capped {
			message = "cap mismatch"
		}
		if c.Expected.Reason != "" && (len(out.Failures) == 0 || out.Failures[0].Reason != c.Expected.Reason) {
			message = "reason mismatch"
		}
		if message == "" {
			passed++
		}
		results = append(results, map[string]any{"id": c.ID, "partition": c.Partition, "success": message == "", "error": message, "elapsed_ms": float64(time.Since(start).Nanoseconds()) / 1e6, "output": out})
	}
	impl, err := os.ReadFile(".checks/check.go")
	if err != nil {
		panic(err)
	}
	report := map[string]any{"example": suite.ID, "task": "detectionMonitor", "phase": "source_bound_contract_validation", "paired_comparison": false, "case_count": len(suite.Cases), "passed": passed, "cases_sha256": fmt.Sprintf("%x", sha256.Sum256(raw)), "implementation_sha256": fmt.Sprintf("%x", sha256.Sum256(impl)), "model_calls": 0, "results": results, "github_run_id": os.Getenv("GITHUB_RUN_ID"), "github_sha": os.Getenv("GITHUB_SHA")}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[2], encoded, 0600); err != nil {
		panic(err)
	}
	fmt.Printf("%d/%d passed\n", passed, len(suite.Cases))
	if passed != len(suite.Cases) {
		os.Exit(1)
	}
}
