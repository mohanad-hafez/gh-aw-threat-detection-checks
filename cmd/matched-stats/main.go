package main

import (
	"encoding/json"
	"os"

	"github.com/github/gh-aw-threat-detection/internal/statreport"
)

func main() {
	data, err := os.ReadFile(".github/matched/stats-fixture.json")
	if err != nil {
		panic(err)
	}
	var fixture struct {
		Inputs struct {
			Summary string          `json:"summary"`
			Stats   json.RawMessage `json:"stats"`
			History json.RawMessage `json:"history"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		panic(err)
	}
	result, err := statreport.Render([]byte(fixture.Inputs.Summary), fixture.Inputs.Stats, fixture.Inputs.History, "", "")
	if err != nil {
		panic(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
