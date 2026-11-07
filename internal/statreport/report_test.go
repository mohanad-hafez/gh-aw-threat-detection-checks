package statreport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func stats(date string, partial bool) []byte {
	return []byte(fmt.Sprintf(`{"date":%q,"repository":"github/gh-aw","totals":{"external_detector_runs":20},"error_rate_pct":10,"soft_failures":{"count":1},"detection_results":{"with_verdict":16,"any_threat":2,"threat_rate_pct":12.5},"collection":{"rates_cover_partial_day":%t,"truncations":[]},"by_workflow":[{"workflow":"clean","runs":10,"failed":0,"no_verdict":0},{"workflow":"missing","runs":6,"failed":0,"no_verdict":3},{"workflow":"failed","runs":4,"failed":2,"no_verdict":0}]}`, date, partial))
}
func TestSummaryPreservedAndBaseline(t *testing.T) {
	summary := []byte("# Original digest\n\nExact source values: **20**\n")
	out, err := Render(summary, stats("2026-11-06", false), nil, "https://example.invalid/1", "1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Body, string(summary)) || !strings.Contains(out.Body, "No history yet; establishing the baseline.") || len(out.History) != 1 || strings.Contains(out.Body, "- clean") {
		t.Fatal(out)
	}
	if strings.Index(out.Body, "- missing") > strings.Index(out.Body, "- failed") {
		t.Fatal("watch list did not rank observed counts")
	}
}
func TestPartialSkipsRateComparisonAndKeepsHistory(t *testing.T) {
	h := []Entry{{Date: "2026-11-05", Runs: 10, Error: 50}}
	b, _ := json.Marshal(h)
	out, err := Render([]byte("digest"), stats("2026-11-06", true), b, "url", "2")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Body, "| Delta |") || !out.History[1].Partial || !strings.Contains(out.Body, "partial day") {
		t.Fatal(out)
	}
}
func TestHistoryReplacesSameDateSkipsPartialAndFuture(t *testing.T) {
	h := []Entry{{Date: "2026-11-04", Runs: 10, Error: 20}, {Date: "2026-11-05", Runs: 999, Partial: true}, {Date: "2026-11-06", Runs: 888}, {Date: "2026-11-07", Runs: 777}}
	b, _ := json.Marshal(h)
	out, err := Render([]byte("digest"), stats("2026-11-06", false), b, "url", "3")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.History) != 4 || out.History[2].Runs != 20 || !strings.Contains(out.Body, "## Change since 2026-11-04") || strings.Contains(out.Body, "888.00") {
		t.Fatal(out)
	}
}
func TestSevenPriorCompleteDaysAndThirtyEntryRetention(t *testing.T) {
	h := []Entry{}
	for day := 1; day <= 31; day++ {
		h = append(h, Entry{Date: fmt.Sprintf("2026-10-%02d", day), Runs: float64(day)})
	}
	b, _ := json.Marshal(h)
	out, err := Render([]byte("digest"), stats("2026-11-06", false), b, "url", "4")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.History) != 30 || !strings.Contains(out.Body, "Previous 7-day mean") || !strings.Contains(out.Body, "28.00") {
		t.Fatal(out)
	}
}
func TestBrokenHistoryAndMissingSummary(t *testing.T) {
	out, err := Render([]byte("digest"), stats("2026-11-06", false), []byte("not-json"), "url", "5")
	if err != nil || !out.HistoryInvalid || !out.Baseline {
		t.Fatal(out, err)
	}
	if _, err := Render(nil, stats("2026-11-06", false), nil, "url", "5"); err == nil {
		t.Fatal("missing summary silently published")
	}
}
