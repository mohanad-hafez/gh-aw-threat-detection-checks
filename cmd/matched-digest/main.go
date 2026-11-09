package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/github/gh-aw-threat-detection/internal/issuedigest"
)

func main() {
	var fixture struct {
		Inputs struct {
			Issues []issuedigest.Issue `json:"issues"`
			Clock  string              `json:"clock"`
			Cache  *issuedigest.State `json:"cache"`
		} `json:"inputs"`
	}
	raw, err := os.ReadFile(".github/matched/digest-fixture.json")
	if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.Inputs.Cache != nil {
		panic("invalid cold-cache fixture")
	}
	now, err := time.Parse(time.RFC3339, fixture.Inputs.Clock)
	if err != nil {
		panic(err)
	}
	state, cold := issuedigest.Load(nil)
	plan, err := issuedigest.Build(state, cold, fixture.Inputs.Issues, nil, now, "")
	if err != nil || plan.Status != "baseline_noop" {
		panic(fmt.Sprintf("expected cold-cache no-op: %v", err))
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": plan.Status,
		"state":  plan.State,
		"writes": 0,
	}); err != nil {
		panic(err)
	}
}
