package monitor

import (
	"encoding/json"
	"fmt"
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
func Plan(in Input) (Output, error) {
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
