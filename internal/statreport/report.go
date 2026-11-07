package statreport

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type Entry struct {
	Date       string  `json:"date"`
	Runs       float64 `json:"external_detector_runs"`
	Error      float64 `json:"error_rate_pct"`
	Soft       float64 `json:"soft_failures"`
	Verdict    float64 `json:"with_verdict"`
	Threat     float64 `json:"any_threat"`
	ThreatRate float64 `json:"threat_rate_pct"`
	Partial    bool    `json:"partial"`
}
type Workflow struct {
	Name    string `json:"workflow"`
	Runs    int    `json:"runs"`
	Failed  int    `json:"failed"`
	Missing int    `json:"no_verdict"`
}
type Stats struct {
	Date       string `json:"date"`
	Repository string `json:"repository"`
	Totals     struct {
		Runs float64 `json:"external_detector_runs"`
	} `json:"totals"`
	Collection struct {
		Partial     bool     `json:"rates_cover_partial_day"`
		Truncations []string `json:"truncations"`
	} `json:"collection"`
	Error float64 `json:"error_rate_pct"`
	Soft  struct {
		Count float64 `json:"count"`
	} `json:"soft_failures"`
	Detection struct {
		Verdict float64 `json:"with_verdict"`
		Threat  float64 `json:"any_threat"`
		Rate    float64 `json:"threat_rate_pct"`
	} `json:"detection_results"`
	Workflows []Workflow `json:"by_workflow"`
}
type Output struct {
	Title          string  `json:"title"`
	Body           string  `json:"body"`
	History        []Entry `json:"history"`
	Baseline       bool    `json:"baseline"`
	Partial        bool    `json:"partial"`
	HistoryInvalid bool    `json:"history_invalid"`
}

func valid(e Entry) bool {
	if _, err := time.Parse("2006-01-02", e.Date); err != nil {
		return false
	}
	for _, n := range []float64{e.Runs, e.Error, e.Soft, e.Verdict, e.Threat, e.ThreatRate} {
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
			return false
		}
	}
	return e.Error <= 100 && e.ThreatRate <= 100
}
func clean(s string) string { return strings.NewReplacer("\n", " ", "\r", " ", "|", "\\|").Replace(s) }
func Render(summary []byte, stats []byte, history []byte, scanURL, runID string) (Output, error) {
	out := Output{}
	if len(summary) == 0 {
		return out, fmt.Errorf("no summary; collector failure requires noop")
	}
	var s Stats
	if err := json.Unmarshal(stats, &s); err != nil {
		return out, fmt.Errorf("collector stats are invalid JSON")
	}
	today := Entry{s.Date, s.Totals.Runs, s.Error, s.Soft.Count, s.Detection.Verdict, s.Detection.Threat, s.Detection.Rate, s.Collection.Partial}
	if !valid(today) || s.Repository == "" {
		return out, fmt.Errorf("collector headline fields are invalid")
	}
	var hist []Entry
	if len(history) > 0 {
		if err := json.Unmarshal(history, &hist); err != nil {
			out.HistoryInvalid = true
			hist = nil
		}
	}
	for _, e := range hist {
		if !valid(e) {
			out.HistoryInvalid = true
			hist = nil
			break
		}
	}
	// Re-runs replace today's entry. Prior comparisons exclude later dates too.
	byDate := map[string]Entry{}
	for _, e := range hist {
		byDate[e.Date] = e
	}
	eligible := []Entry{}
	for date, e := range byDate {
		if date < s.Date && !e.Partial {
			eligible = append(eligible, e)
		}
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].Date < eligible[j].Date })
	out.Baseline = len(eligible) == 0
	out.Partial = today.Partial
	var body strings.Builder
	fmt.Fprintf(&body, "%.0f external-detector runs analysed; detection-job error rate %.2f%%; %.0f soft failures; threat rate %.2f%%.\n", today.Runs, today.Error, today.Soft, today.ThreatRate)
	if len(s.Collection.Truncations) > 0 {
		body.WriteString("\n**Collection truncated: counts are lower bounds; rates describe only the inspected part of the day.**\n")
		for _, note := range s.Collection.Truncations {
			fmt.Fprintf(&body, "- %s\n", clean(note))
		}
	}
	body.WriteString("\n## Summary\n\n")
	body.Write(summary)
	if summary[len(summary)-1] != '\n' {
		body.WriteByte('\n')
	}
	if today.Partial {
		body.WriteString("\n## Change since previous collection\n\nToday's collection covers a partial day; no like-for-like rate comparison is reported.\n")
	} else if out.Baseline {
		body.WriteString("\n## Change since previous collection\n\nNo history yet; establishing the baseline.\n")
	} else {
		previous := eligible[len(eligible)-1]
		fmt.Fprintf(&body, "\n## Change since %s\n\n", previous.Date)
		names := []string{"External detector runs", "Error rate (%)", "Soft failures", "Runs with verdict", "Any threat", "Threat rate (%)"}
		values := func(e Entry) []float64 { return []float64{e.Runs, e.Error, e.Soft, e.Verdict, e.Threat, e.ThreatRate} }
		before, now := values(previous), values(today)
		means := make([]float64, len(names))
		withMean := len(eligible) >= 7
		if withMean {
			for _, e := range eligible[len(eligible)-7:] {
				for i, n := range values(e) {
					means[i] += n / 7
				}
			}
		}
		body.WriteString("| Metric | Previous | Today | Delta |")
		if withMean {
			body.WriteString(" Previous 7-day mean |")
		}
		body.WriteString("\n|---|---:|---:|---:|")
		if withMean {
			body.WriteString("---:|")
		}
		body.WriteByte('\n')
		for i, name := range names {
			fmt.Fprintf(&body, "| %s | %.2f | %.2f | %+.2f |", name, before[i], now[i], now[i]-before[i])
			if withMean {
				fmt.Fprintf(&body, " %.2f |", means[i])
			}
			body.WriteByte('\n')
		}
	}
	body.WriteString("\n## Watch list\n\n")
	rows := append([]Workflow{}, s.Workflows...)
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Failed+a.Missing != b.Failed+b.Missing {
			return a.Failed+a.Missing > b.Failed+b.Missing
		}
		if a.Failed != b.Failed {
			return a.Failed > b.Failed
		}
		return a.Name < b.Name
	})
	watch := 0
	for _, w := range rows {
		if w.Failed+w.Missing == 0 || watch == 5 {
			continue
		}
		fmt.Fprintf(&body, "- %s — %d failed, %d without a verdict, out of %d runs\n", clean(w.Name), w.Failed, w.Missing, w.Runs)
		watch++
	}
	if watch == 0 {
		body.WriteString("None\n")
	}
	fmt.Fprintf(&body, "\nCollected by: %s\nFull data: the detection-stats-%s artifact on that run.", scanURL, runID)
	byDate[s.Date] = today
	out.History = []Entry{}
	for _, e := range byDate {
		out.History = append(out.History, e)
	}
	sort.Slice(out.History, func(i, j int) bool { return out.History[i].Date < out.History[j].Date })
	if len(out.History) > 30 {
		out.History = out.History[len(out.History)-30:]
	}
	out.Title = "[detection-stats] Detection stats for " + s.Repository + " - " + s.Date
	out.Body = body.String()
	return out, nil
}
