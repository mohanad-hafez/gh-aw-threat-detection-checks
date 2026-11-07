package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Target = "mohanad-hafez/gh-aw-threat-detection-checks"
const Source = "github/gh-aw"

type Client struct {
	token       string
	base        string
	http        *http.Client
	allowLogURL func(*url.URL) bool
	Requests    int
	exhausted   bool
}

type HTTPError struct {
	Operation string
	Status    int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d; inspect the saved receipt before another attempt", e.Operation, e.Status)
}

func NewClient(token string) *Client {
	return &Client{token: token, base: "https://api.github.com", http: &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, allowLogURL: func(u *url.URL) bool {
		h := strings.ToLower(u.Hostname())
		return u.Scheme == "https" && (strings.HasSuffix(h, ".blob.core.windows.net") || strings.HasSuffix(h, ".actions.githubusercontent.com") || strings.HasSuffix(h, ".githubusercontent.com"))
	}}
}

func (c *Client) api(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	if c.exhausted || c.Requests >= 300 {
		return nil, fmt.Errorf("GitHub request budget reached; preserve partial observations and inspect rate limits")
	}
	var body io.Reader
	if payload != nil {
		b, e := json.Marshal(payload)
		if e != nil {
			return nil, fmt.Errorf("encode GitHub request: %w", e)
		}
		body = bytes.NewReader(b)
	}
	request, e := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if e != nil {
		return nil, fmt.Errorf("construct GitHub request")
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("Content-Type", "application/json")
	c.Requests++
	response, e := c.http.Do(request)
	if e != nil {
		return nil, fmt.Errorf("GitHub transport failed; no automatic replay was attempted")
	}
	if remaining, e := strconv.Atoi(response.Header.Get("X-RateLimit-Remaining")); e == nil && remaining < 100 {
		c.exhausted = true
	}
	return response, nil
}

func (c *Client) json(ctx context.Context, path string, destination any) error {
	response, e := c.api(ctx, http.MethodGet, path, nil)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return &HTTPError{"read GitHub metadata", response.StatusCode}
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1))
	if e != nil || len(data) > 8*1024*1024 {
		return fmt.Errorf("GitHub metadata exceeded the read bound or could not be read")
	}
	if e = json.Unmarshal(data, destination); e != nil {
		return fmt.Errorf("GitHub metadata was not valid JSON")
	}
	return nil
}

type LogObservation struct {
	JobID  int64  `json:"job_id"`
	Lines  int    `json:"tail_lines"`
	Bytes  int    `json:"transferred_bytes"`
	SHA256 string `json:"tail_sha256,omitempty"`
	Marker string `json:"technical_marker,omitempty"`
	Error  string `json:"error,omitempty"`
}
type RunObservation struct {
	RunID               int64  `json:"run_id"`
	Name                string `json:"workflow"`
	Conclusion          string `json:"run_conclusion"`
	DetectionID         int64  `json:"detection_job_id,omitempty"`
	DetectionConclusion string `json:"detection_conclusion,omitempty"`
	Error               string `json:"error,omitempty"`
}
type Evidence struct {
	Now        string           `json:"window_end"`
	Since      string           `json:"window_start"`
	Listed     int              `json:"listed_runs"`
	Selected   int              `json:"selected_runs"`
	Runs       []RunObservation `json:"runs"`
	Logs       []LogObservation `json:"logs"`
	ReadErrors int              `json:"read_errors"`
	Requests   int              `json:"github_api_requests"`
}

// Tail reads a bounded byte range and returns at most the source's last 200 lines.
// Raw bytes, storage URLs and model-authored reasons never enter Evidence.
func (c *Client) Tail(ctx context.Context, jobID int64) (string, LogObservation, error) {
	observation := LogObservation{JobID: jobID}
	response, e := c.api(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/actions/jobs/%d/logs", Source, jobID), nil)
	if e != nil {
		return "", observation, e
	}
	location := response.Header.Get("Location")
	status := response.StatusCode
	response.Body.Close()
	if status != 302 && status != 307 {
		return "", observation, &HTTPError{"resolve job log tail", status}
	}
	storage, e := url.Parse(location)
	if e != nil || !c.allowLogURL(storage) {
		return "", observation, fmt.Errorf("job log redirect is outside the approved storage hosts")
	}
	for size := int64(65536); size <= 1048576; size *= 2 {
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, storage.String(), nil)
		if e != nil {
			return "", observation, fmt.Errorf("construct bounded log request")
		}
		request.Header.Set("Range", fmt.Sprintf("bytes=-%d", size))
		part, e := c.http.Do(request)
		if e != nil {
			return "", observation, fmt.Errorf("log storage transport failed")
		}
		if part.StatusCode != http.StatusPartialContent {
			part.Body.Close()
			return "", observation, &HTTPError{"read bounded job log range", part.StatusCode}
		}
		var start, end, total int64
		_, rangeError := fmt.Sscanf(part.Header.Get("Content-Range"), "bytes %d-%d/%d", &start, &end, &total)
		raw, readError := io.ReadAll(io.LimitReader(part.Body, size+1))
		part.Body.Close()
		observation.Bytes += len(raw)
		if rangeError != nil || readError != nil || int64(len(raw)) > size || start < 0 || end != total-1 || end-start+1 != int64(len(raw)) {
			return "", observation, fmt.Errorf("log storage returned an invalid or incomplete byte range")
		}
		lines := strings.Split(strings.TrimRight(string(raw), "\r\n"), "\n")
		// A nonzero range can start mid-line. Require enough complete trailing lines.
		if start > 0 && len(lines) <= 200 {
			continue
		}
		if len(lines) > 200 {
			lines = lines[len(lines)-200:]
		}
		tail := strings.Join(lines, "\n")
		observation.Lines = len(lines)
		observation.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(tail)))
		for _, marker := range []string{"threat-detect binary not found on PATH", "reason=agent_failure", "reason=parse_error"} {
			if strings.Contains(tail, marker) {
				observation.Marker = marker
				break
			}
		}
		return tail, observation, nil
	}
	return "", observation, fmt.Errorf("last 200 complete log lines exceed the bounded range allowance")
}

func (c *Client) Collect(ctx context.Context, now time.Time, scanURL string) (Input, Evidence, error) {
	evidence := Evidence{Now: now.UTC().Format(time.RFC3339), Since: now.Add(-24 * time.Hour).UTC().Format(time.RFC3339), Runs: []RunObservation{}, Logs: []LogObservation{}}
	input := Input{Now: evidence.Now, ScanURL: scanURL, Runs: []Run{}}
	var listing struct {
		Runs []Run `json:"workflow_runs"`
	}
	if e := c.json(ctx, "/repos/"+Source+"/actions/runs?status=completed&per_page=80", &listing); e != nil {
		return input, evidence, e
	}
	evidence.Listed = len(listing.Runs)
	recent := func(s string) bool {
		t := parse(s)
		return !t.IsZero() && !t.Before(now.Add(-24*time.Hour)) && !t.After(now)
	}
	for _, r := range listing.Runs {
		if r.Status == "completed" && (recent(r.Created) || recent(r.Updated)) {
			input.Runs = append(input.Runs, r)
		}
	}
	sort.SliceStable(input.Runs, func(i, j int) bool { return parse(input.Runs[i].Created).After(parse(input.Runs[j].Created)) })
	if len(input.Runs) > 80 {
		input.Runs = input.Runs[:80]
	}
	evidence.Selected = len(input.Runs)
	soft := 0
	seen := map[int64]bool{}
	authStopped := false
	for i := range input.Runs {
		r := &input.Runs[i]
		observation := RunObservation{RunID: r.ID, Name: r.Name, Conclusion: r.Conclusion}
		if seen[r.ID] || r.Conclusion == "cancelled" || r.Conclusion == "skipped" {
			evidence.Runs = append(evidence.Runs, observation)
			continue
		}
		seen[r.ID] = true
		if authStopped {
			observation.Error = "not inspected after an authorization failure"
			evidence.ReadErrors++
			evidence.Runs = append(evidence.Runs, observation)
			continue
		}
		jobsComplete := false
		for page := 1; page <= 10; page++ {
			var listing struct {
				Jobs  []Job `json:"jobs"`
				Total int   `json:"total_count"`
			}
			e := c.json(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?filter=latest&per_page=100&page=%d", Source, r.ID, page), &listing)
			if e != nil {
				observation.Error = e.Error()
				if h, ok := e.(*HTTPError); ok && (h.Status == 401 || h.Status == 403) {
					authStopped = true
				}
				break
			}
			r.Jobs = append(r.Jobs, listing.Jobs...)
			if len(r.Jobs) >= listing.Total {
				jobsComplete = true
				break
			}
		}
		if !jobsComplete {
			if observation.Error == "" {
				observation.Error = "job pagination bound reached"
			}
			evidence.ReadErrors++
		}
		for j := range r.Jobs {
			job := &r.Jobs[j]
			if job.Name != "detection" {
				continue
			}
			observation.DetectionID = job.ID
			observation.DetectionConclusion = job.Conclusion
			if job.Conclusion == "success" && soft < 30 {
				soft++
				tail, log, e := c.Tail(ctx, job.ID)
				if e != nil {
					job.LogError = e.Error()
					log.Error = e.Error()
					evidence.ReadErrors++
				} else {
					job.Log = &tail
				}
				evidence.Logs = append(evidence.Logs, log)
			}
			break
		}
		evidence.Runs = append(evidence.Runs, observation)
	}
	evidence.Requests = c.Requests
	return input, evidence, nil
}

type Issue struct {
	Number int64  `json:"number"`
	URL    string `json:"html_url"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

func (c *Client) CreateIssue(ctx context.Context, title, body string) (Issue, error) {
	var issue Issue
	response, e := c.api(ctx, http.MethodPost, "/repos/"+Target+"/issues", map[string]any{"title": "[detection-failures] " + title, "body": body, "labels": []string{"automation", "detection-monitor"}})
	if e != nil {
		return issue, e
	}
	defer response.Body.Close()
	if response.StatusCode != 201 {
		return issue, &HTTPError{"create owned report issue", response.StatusCode}
	}
	if e = json.NewDecoder(io.LimitReader(response.Body, 1048576)).Decode(&issue); e != nil {
		return issue, fmt.Errorf("created issue response could not be decoded; delivery requires inspection")
	}
	return issue, nil
}
func (c *Client) ReadIssue(ctx context.Context, number int64) (Issue, error) {
	var issue Issue
	e := c.json(ctx, fmt.Sprintf("/repos/%s/issues/%d", Target, number), &issue)
	return issue, e
}
