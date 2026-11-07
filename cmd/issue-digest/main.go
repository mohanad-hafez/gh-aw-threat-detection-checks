package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/github/gh-aw-threat-detection/internal/issuedigest"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const target = "mohanad-hafez/gh-aw-threat-detection-checks"

func save(path string, value any) error {
	raw, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if e = os.WriteFile(path+".tmp", append(raw, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func run() error {
	if os.Getenv("GITHUB_REPOSITORY") != target {
		return fmt.Errorf("run the digest only in the owned experimental fork")
	}
	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" || strings.Trim(runID, "0123456789") != "" {
		return fmt.Errorf("a numeric Actions run identity is required")
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return fmt.Errorf("runtime GitHub token missing; set GH_TOKEN in the trusted workflow step")
	}
	receipt := map[string]any{"status": "reading", "model_calls": 0, "source": "github/gh-aw", "target": target, "upstream_bodies_fetched": 0}
	fail := func(e error) error {
		receipt["error"] = e.Error()
		if saveErr := save("digest-receipt.json", receipt); saveErr != nil {
			return saveErr
		}
		return e
	}
	if old, e := os.ReadFile("digest-state/attempt.json"); e == nil {
		var attempt map[string]any
		if json.Unmarshal(old, &attempt) != nil {
			return fail(fmt.Errorf("cached attempt is invalid; inspect before running again"))
		}
		status, _ := attempt["status"].(string)
		if status != "created_verified" && status != "baseline_noop" && status != "no_new_issues" {
			receipt["status"] = "inspection_required"
			receipt["prior_attempt_sha256"] = fmt.Sprintf("%x", sha256.Sum256(old))
			return fail(fmt.Errorf("prior digest delivery needs inspection; no automatic replay"))
		}
	} else if !os.IsNotExist(e) {
		return fail(fmt.Errorf("cannot read prior attempt; leave state unchanged"))
	}
	raw, e := os.ReadFile("digest-state/reported-issues.json")
	if e != nil && !os.IsNotExist(e) {
		return fail(fmt.Errorf("cannot read reported state; leave it unchanged"))
	}
	state, cold := issuedigest.Load(raw)
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	requests := 0
	request := func(method, path string, payload any) ([]byte, int, error) {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, bytes.NewReader(encoded))
		if err != nil {
			return nil, 0, fmt.Errorf("cannot construct GitHub request")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		requests++
		response, err := client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("GitHub transport failed; inspect retained delivery state")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 2097153))
		if err != nil || len(data) > 2097152 {
			return nil, response.StatusCode, fmt.Errorf("GitHub response incomplete or beyond read limit")
		}
		return data, response.StatusCode, nil
	}
	query := func(text string, destination any) error {
		data, status, err := request("POST", "/graphql", map[string]string{"query": text})
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("metadata query returned HTTP %d; leave state unchanged", status)
		}
		var envelope struct {
			Data   json.RawMessage   `json:"data"`
			Errors []json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(data, &envelope) != nil || len(envelope.Errors) > 0 || string(envelope.Data) == "null" || len(envelope.Data) == 0 {
			return fmt.Errorf("metadata query returned errors or filtered data; leave state unchanged")
		}
		if json.Unmarshal(envelope.Data, destination) != nil {
			return fmt.Errorf("metadata shape invalid; leave state unchanged")
		}
		return nil
	}
	var upstream struct {
		Repository *struct {
			Issues struct {
				Total int                 `json:"totalCount"`
				Nodes []issuedigest.Issue `json:"nodes"`
			} `json:"issues"`
		} `json:"repository"`
	}
	e = query(`{repository(owner:"github",name:"gh-aw"){issues(first:50,states:[OPEN,CLOSED],labels:["threat-detection"],orderBy:{field:UPDATED_AT,direction:DESC}){totalCount nodes{number title state createdAt updatedAt url author{login} labels(first:100){nodes{name} pageInfo{hasNextPage}}}}}}`, &upstream)
	if e != nil {
		receipt["status"] = "incomplete_reads"
		return fail(e)
	}
	if upstream.Repository == nil {
		return fail(fmt.Errorf("upstream repository inaccessible; leave state unchanged"))
	}
	issues := upstream.Repository.Issues.Nodes
	expected := upstream.Repository.Issues.Total
	if expected > 50 {
		expected = 50
	}
	if len(issues) != expected {
		return fail(fmt.Errorf("upstream issue response incomplete; leave state unchanged"))
	}
	receipt["issues"] = issues
	receipt["source_total_matching"] = upstream.Repository.Issues.Total
	digests := []issuedigest.Digest{}
	if !cold && len(state.Pending) > 0 {
		var local struct {
			Repository *struct {
				Issues struct {
					Nodes []issuedigest.Digest `json:"nodes"`
				} `json:"issues"`
			} `json:"repository"`
		}
		e = query(`{repository(owner:"mohanad-hafez",name:"gh-aw-threat-detection-checks"){issues(first:10,states:[OPEN,CLOSED],labels:["gh-aw-issue-digest"],orderBy:{field:CREATED_AT,direction:DESC}){nodes{number createdAt}}}}`, &local)
		if e != nil {
			return fail(e)
		}
		if local.Repository == nil {
			return fail(fmt.Errorf("local digest inventory inaccessible; leave state unchanged"))
		}
		digests = local.Repository.Issues.Nodes
		receipt["local_digest_inventory"] = digests
	}
	plan, e := issuedigest.Build(state, cold, issues, digests, time.Now().UTC(), "https://github.com/"+target+"/actions/runs/"+runID)
	if e != nil {
		return fail(e)
	}
	receipt["plan"] = plan
	receipt["github_api_requests"] = requests
	receipt["status"] = plan.Status
	if len(plan.Body) > 60000 {
		return fail(fmt.Errorf("digest exceeds bounded issue length; inspect before publication"))
	}
	if e = save("digest-state/reported-issues.json", plan.State); e != nil {
		return fail(e)
	}
	if plan.Status != "digest_planned" {
		if e = save("digest-state/attempt.json", map[string]string{"status": plan.Status}); e != nil {
			return fail(e)
		}
		return save("digest-receipt.json", receipt)
	}
	payload := map[string]any{"title": plan.Title, "body": plan.Body, "labels": []string{"automation", "gh-aw-issue-digest"}}
	encoded, _ := json.Marshal(payload)
	receipt["request_sha256"] = fmt.Sprintf("%x", sha256.Sum256(encoded))
	receipt["status"] = "delivery_pending"
	if e = save("digest-state/attempt.json", receipt); e != nil {
		return fail(e)
	}
	if e = save("digest-receipt.json", receipt); e != nil {
		return e
	}
	data, status, e := request("POST", "/repos/"+target+"/issues", payload)
	if e != nil || status != 201 {
		receipt["status"] = "delivery_uncertain"
		if e == nil {
			e = fmt.Errorf("owned digest POST returned HTTP %d; inspect before replay", status)
		}
		_ = save("digest-state/attempt.json", receipt)
		return fail(e)
	}
	var issue struct {
		Number int    `json:"number"`
		URL    string `json:"html_url"`
		Title  string `json:"title"`
		Body   string `json:"body"`
	}
	if json.Unmarshal(data, &issue) != nil {
		receipt["status"] = "delivery_uncertain"
		_ = save("digest-state/attempt.json", receipt)
		return fail(fmt.Errorf("created issue response invalid; inspect delivery"))
	}
	receipt["issue"] = issue
	receipt["status"] = "created_readback_pending"
	if e = save("digest-state/attempt.json", receipt); e != nil {
		return fail(e)
	}
	data, status, e = request("GET", fmt.Sprintf("/repos/%s/issues/%d", target, issue.Number), nil)
	if e != nil {
		return fail(e)
	}
	var readback struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if status != 200 || json.Unmarshal(data, &readback) != nil || readback.Title != plan.Title || readback.Body != plan.Body {
		return fail(fmt.Errorf("digest readback incomplete or different; inspect before another run"))
	}
	receipt["status"] = "created_verified"
	receipt["github_api_requests"] = requests
	if e = save("digest-state/attempt.json", receipt); e != nil {
		return fail(e)
	}
	return save("digest-receipt.json", receipt)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
