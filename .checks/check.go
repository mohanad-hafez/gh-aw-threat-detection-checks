package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	monitorrules "github.com/github/gh-aw-threat-detection/internal/monitor"
	"os"
	"time"
)

type Step = monitorrules.Step
type Job = monitorrules.Job
type Run = monitorrules.Run
type Input = monitorrules.Input
type Failure = monitorrules.Failure
type Read = monitorrules.Read
type Output = monitorrules.Output

func monitor(in Input) (Output, error) { return monitorrules.Plan(in) }

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
	impl, err := os.ReadFile("internal/monitor/rules.go")
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
