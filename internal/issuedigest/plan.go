package issuedigest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Issue struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	Created string `json:"createdAt"`
	Updated string `json:"updatedAt"`
	URL     string `json:"url"`
	Author  *struct {
		Login string `json:"login"`
	} `json:"author"`
	Labels struct {
		Nodes []struct {
			Name string `json:"name"`
		} `json:"nodes"`
		PageInfo struct {
			HasNext bool `json:"hasNextPage"`
		} `json:"pageInfo"`
	} `json:"labels"`
}
type Digest struct {
	Created string `json:"createdAt"`
	Number  int    `json:"number"`
}
type State struct {
	Reported     []int  `json:"reported_issue_numbers"`
	Pending      []int  `json:"pending_issue_numbers"`
	PendingSince string `json:"pending_since"`
	LastRun      string `json:"last_run_at"`
}
type Plan struct {
	Status           string `json:"status"`
	State            State  `json:"state"`
	Title            string `json:"title,omitempty"`
	Body             string `json:"body,omitempty"`
	Observed         []int  `json:"observed_issue_numbers"`
	Baseline         bool   `json:"baseline"`
	PendingPromotion string `json:"pending_promotion_rule"`
}

func Load(raw []byte) (State, bool) {
	var s State
	if json.Unmarshal(raw, &s) != nil || s.Reported == nil || s.Pending == nil {
		return s, true
	}
	for _, n := range append(append([]int{}, s.Reported...), s.Pending...) {
		if n <= 0 {
			return s, true
		}
	}
	if len(s.Pending) > 0 {
		if _, e := time.Parse(time.RFC3339, s.PendingSince); e != nil {
			return s, true
		}
	}
	return s, false
}
func capSet(set map[int]bool) []int {
	out := []int{}
	for n := range set {
		out = append(out, n)
	}
	sort.Ints(out)
	if len(out) > 500 {
		out = out[len(out)-500:]
	}
	return out
}
func escape(s string) string {
	return strings.NewReplacer("\\", "\\\\", "`", "\\`", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;", "@", "&#64;", "\n", " ", "\r", " ").Replace(s)
}
func Build(s State, baseline bool, issues []Issue, digests []Digest, now time.Time, scanURL string) (Plan, error) {
	out := Plan{Observed: []int{}, Baseline: baseline, PendingPromotion: "Source literal rule: any of10latest labelled local digests created at/after pending_since; not independent content verification"}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Updated > issues[j].Updated })
	if len(issues) > 50 {
		issues = issues[:50]
	}
	confirmed := map[int]bool{}
	if !baseline {
		for _, n := range s.Reported {
			confirmed[n] = true
		}
		if len(s.Pending) > 0 {
			since, _ := time.Parse(time.RFC3339, s.PendingSince)
			if len(digests) > 10 {
				digests = digests[:10]
			}
			for _, d := range digests {
				created, e := time.Parse(time.RFC3339, d.Created)
				if e != nil {
					return out, fmt.Errorf("local digest timestamp invalid; leave state unchanged and inspect metadata")
				}
				if !created.Before(since) {
					for _, n := range s.Pending {
						confirmed[n] = true
					}
					break
				}
			}
		}
	}
	fresh := []Issue{}
	seen := map[int]bool{}
	for _, issue := range issues {
		if issue.Number <= 0 || issue.Author == nil || issue.Author.Login == "" || issue.Labels.PageInfo.HasNext {
			return out, fmt.Errorf("issue metadata incomplete; leave state unchanged and inspect author/label coverage")
		}
		if _, e := time.Parse(time.RFC3339, issue.Created); e != nil {
			return out, fmt.Errorf("issue creation time invalid; leave state unchanged")
		}
		if _, e := time.Parse(time.RFC3339, issue.Updated); e != nil {
			return out, fmt.Errorf("issue update time invalid; leave state unchanged")
		}
		issue.State = strings.ToLower(issue.State)
		if issue.State != "open" && issue.State != "closed" {
			return out, fmt.Errorf("unknown issue state; expected OPEN or CLOSED")
		}
		if seen[issue.Number] {
			continue
		}
		seen[issue.Number] = true
		out.Observed = append(out.Observed, issue.Number)
		if baseline {
			confirmed[issue.Number] = true
		} else if !confirmed[issue.Number] {
			fresh = append(fresh, issue)
		}
	}
	out.State = State{Reported: capSet(confirmed), Pending: []int{}, LastRun: now.UTC().Format(time.RFC3339)}
	if baseline {
		out.Status = "baseline_noop"
		return out, nil
	}
	if len(fresh) == 0 {
		out.Status = "no_new_issues"
		return out, nil
	}
	closed := 0
	lines := []string{}
	for _, i := range fresh {
		if i.State == "closed" {
			closed++
		}
		out.State.Pending = append(out.State.Pending, i.Number)
		labels := []string{}
		for _, l := range i.Labels.Nodes {
			if l.Name != "threat-detection" {
				labels = append(labels, escape(l.Name))
			}
		}
		extra := ""
		if len(labels) > 0 {
			extra = ", labels: " + strings.Join(labels, ", ")
		}
		lines = append(lines, fmt.Sprintf("- [#%d](https://github.com/github/gh-aw/issues/%d) — %s — %s, opened %s by `@%s`%s", i.Number, i.Number, escape(i.Title), i.State, i.Created[:10], i.Author.Login, extra))
	}
	out.State.PendingSince = out.State.LastRun
	out.Status = "digest_planned"
	out.Title = "[gh-aw-issues] New gh-aw threat-detection issues - " + now.UTC().Format("2006-01-02")
	out.Body = fmt.Sprintf("%d new `threat-detection` issues found in `github/gh-aw`; %d already closed.\n\n## Issues\n\n%s\n\n## Why this matters\n\nThis repository ships the `threat-detect` binary consumed by `gh-aw`, so these issues may require follow-up work here.\n\nScanned: %s", len(fresh), closed, strings.Join(lines, "\n"), scanURL)
	return out, nil
}
