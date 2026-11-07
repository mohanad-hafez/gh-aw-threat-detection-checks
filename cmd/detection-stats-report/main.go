package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/github/gh-aw-threat-detection/internal/statreport"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const target = "mohanad-hafez/gh-aw-threat-detection-checks"

func write(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if e = os.WriteFile(path+".tmp", append(b, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func run() error {
	if os.Getenv("GITHUB_REPOSITORY") != target {
		return fmt.Errorf("report publishing is restricted to the owned experimental fork")
	}
	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" || strings.Trim(runID, "0123456789") != "" {
		return fmt.Errorf("valid Actions run identity required")
	}
	if _, e := os.Stat("stats-report-receipt.json"); !os.IsNotExist(e) {
		return fmt.Errorf("existing receipt requires inspection before another execution")
	}
	receipt := map[string]any{"status": "reading", "model_calls": 0, "target": target}
	fail := func(e error) error {
		receipt["error"] = e.Error()
		if saveErr := write("stats-report-receipt.json", receipt); saveErr != nil {
			return saveErr
		}
		return e
	}
	// Primary summary first; absence is the source's documented noop.
	summary, e := os.ReadFile("stats-input/summary.md")
	if os.IsNotExist(e) {
		receipt["status"] = "noop_no_summary"
		return write("stats-report-receipt.json", receipt)
	}
	if e != nil {
		return fail(fmt.Errorf("cannot read source summary"))
	}
	stats, e := os.ReadFile("stats-input/stats.json")
	if e != nil {
		return fail(fmt.Errorf("cannot read source headline metrics"))
	}
	history, e := os.ReadFile("stats-history/history.json")
	if e != nil && !os.IsNotExist(e) {
		return fail(fmt.Errorf("cannot read history"))
	}
	output, e := statreport.Render(summary, stats, history, "https://github.com/"+target+"/actions/runs/"+runID, runID)
	if e != nil {
		return fail(e)
	}
	receipt["summary_sha256"] = fmt.Sprintf("%x", sha256.Sum256(summary))
	receipt["stats_sha256"] = fmt.Sprintf("%x", sha256.Sum256(stats))
	receipt["output"] = output
	if e = write("stats-history/history.json", output.History); e != nil {
		return fail(e)
	}
	if len(output.Body) > 60000 {
		return fail(fmt.Errorf("rendered issue exceeds the bounded publish allowance"))
	}
	payload := map[string]any{"title": output.Title, "body": output.Body, "labels": []string{"automation", "detection-stats"}}
	encoded, e := json.Marshal(payload)
	if e != nil {
		return fail(e)
	}
	receipt["request_sha256"] = fmt.Sprintf("%x", sha256.Sum256(encoded))
	receipt["status"] = "delivery_pending"
	if e = write("stats-report-receipt.json", receipt); e != nil {
		return e
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return fail(fmt.Errorf("runtime token missing; no publish attempted"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(method, path string, data []byte) ([]byte, int, error) {
		req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com/repos/"+target+path, bytes.NewReader(data))
		if err != nil {
			return nil, 0, fmt.Errorf("cannot construct owned report request")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("report transport failed; inspect delivery before retry")
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1048577))
		if err != nil || len(b) > 1048576 {
			return nil, resp.StatusCode, fmt.Errorf("report response was incomplete or exceeded the read bound")
		}
		return b, resp.StatusCode, nil
	}
	data, status, e := request("POST", "/issues", encoded)
	if e != nil || status != 201 {
		receipt["status"] = "delivery_uncertain"
		if e == nil {
			e = fmt.Errorf("owned issue POST returned HTTP %d; inspect before retry", status)
		}
		return fail(e)
	}
	var issue struct {
		Number int64  `json:"number"`
		URL    string `json:"html_url"`
		Title  string `json:"title"`
		Body   string `json:"body"`
	}
	if e = json.Unmarshal(data, &issue); e != nil {
		receipt["status"] = "delivery_uncertain"
		return fail(fmt.Errorf("created issue response invalid; inspect delivery"))
	}
	receipt["issue"] = issue
	receipt["status"] = "created_readback_pending"
	if e = write("stats-report-receipt.json", receipt); e != nil {
		return e
	}
	data, status, e = request("GET", fmt.Sprintf("/issues/%d", issue.Number), nil)
	if e != nil {
		return fail(e)
	}
	if status != 200 {
		return fail(fmt.Errorf("readback returned HTTP %d", status))
	}
	var readback struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if e = json.Unmarshal(data, &readback); e != nil {
		return fail(fmt.Errorf("readback was not valid JSON"))
	}
	if readback.Title != output.Title || readback.Body != output.Body {
		return fail(fmt.Errorf("issue readback differs from requested report"))
	}
	receipt["status"] = "created_verified"
	return write("stats-report-receipt.json", receipt)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
