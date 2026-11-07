package issuedigest

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func sample(n int, state string) Issue {
	var i Issue
	i.Number = n
	i.Title = "metadata @mention [text]"
	i.State = state
	i.Created = "2026-01-01T00:00:00Z"
	i.Updated = fmt.Sprintf("2026-11-07T12:00:%02dZ", n%60)
	i.Author = &struct {
		Login string `json:"login"`
	}{"author"}
	return i
}
func TestColdBaselineHasNoDigest(t *testing.T) {
	p, e := Build(State{}, true, []Issue{sample(1, "CLOSED"), sample(2, "OPEN")}, nil, time.Now(), "url")
	if e != nil || p.Status != "baseline_noop" || p.Body != "" || len(p.State.Reported) != 2 || len(p.State.Pending) != 0 {
		t.Fatal(p, e)
	}
}
func TestPendingTimestampRuleAndFailedPublication(t *testing.T) {
	s := State{Reported: []int{1}, Pending: []int{2}, PendingSince: "2026-11-07T11:00:00Z"}
	now, _ := time.Parse(time.RFC3339, "2026-11-07T13:00:00Z")
	issues := []Issue{sample(1, "OPEN"), sample(2, "CLOSED"), sample(3, "OPEN")}
	p, e := Build(s, false, issues, []Digest{{Created: "2026-11-07T12:00:00Z"}}, now, "url")
	if e != nil || len(p.State.Pending) != 1 || p.State.Pending[0] != 3 || len(p.State.Reported) != 2 {
		t.Fatal(p, e)
	}
	p, e = Build(s, false, issues, nil, now, "url")
	if e != nil || len(p.State.Pending) != 2 || !strings.Contains(p.Body, "1 already closed") {
		t.Fatal(p, e)
	}
}
func TestCapAndDataEscaping(t *testing.T) {
	set := map[int]bool{}
	for n := 1; n <= 600; n++ {
		set[n] = true
	}
	s := State{Reported: capSet(set), Pending: []int{}}
	if len(s.Reported) != 500 || s.Reported[0] != 101 {
		t.Fatal(s)
	}
	p, e := Build(s, false, []Issue{sample(999, "OPEN")}, nil, time.Now(), "url")
	if e != nil || strings.Contains(p.Body, "metadata @mention") || !strings.Contains(p.Body, "by `@author`") {
		t.Fatal(p, e)
	}
}
func TestBadStateColdAndPartialMetadataFails(t *testing.T) {
	_, cold := Load([]byte(`{"reported_issue_numbers":"bad"}`))
	if !cold {
		t.Fatal("corrupt state not detected")
	}
	i := sample(1, "OPEN")
	i.Labels.PageInfo.HasNext = true
	if _, e := Build(State{}, true, []Issue{i}, nil, time.Now(), "url"); e == nil {
		t.Fatal("truncated labels silently accepted")
	}
}
