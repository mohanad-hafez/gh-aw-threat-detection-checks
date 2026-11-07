package monitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTailBoundAndCredentialIsolation(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			text := "reason=agent_failure\n" + strings.Repeat("ordinary observation\n", 250)
			storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("credential forwarded to storage")
				}
				if r.Header.Get("Range") != "bytes=-65536" {
					t.Error("unbounded storage read")
				}
				if valid {
					w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(text)-1, len(text)))
					w.WriteHeader(206)
				}
				_, _ = fmt.Fprint(w, text)
			}))
			defer storage.Close()
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing API authentication")
				}
				w.Header().Set("Location", storage.URL)
				w.WriteHeader(302)
			}))
			defer api.Close()
			c := NewClient("test-token")
			c.base = api.URL
			c.http = api.Client()
			c.http.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
			c.allowLogURL = func(u *url.URL) bool { return u.String() == storage.URL }
			tail, obs, err := c.Tail(context.Background(), 1)
			if !valid {
				if err == nil {
					t.Fatal("ignored range accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if obs.Lines != 200 || strings.Contains(tail, "reason=agent_failure") || obs.Marker != "" {
				t.Fatal("observed bytes outside source tail")
			}
		})
	}
}

func TestIncompleteReadCannotBecomeCleanEvidence(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/jobs") {
			w.WriteHeader(403)
			return
		}
		_, _ = fmt.Fprint(w, `{"workflow_runs":[{"id":1,"name":"sample","status":"completed","conclusion":"success","created_at":"2026-11-07T12:00:00Z"}]}`)
	}))
	defer api.Close()
	c := NewClient("test-token")
	c.base = api.URL
	c.http = api.Client()
	input, ev, err := c.Collect(context.Background(), parse("2026-11-07T13:00:00Z"), "https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if ev.ReadErrors != 1 || len(input.Runs) != 1 {
		t.Fatal("incomplete metadata silently discarded")
	}
}

func TestMissingLogFailsPlan(t *testing.T) {
	_, err := Plan(Input{Now: "2026-11-07T13:00:00Z", Runs: []Run{{ID: 1, Status: "completed", Created: "2026-11-07T12:00:00Z", Jobs: []Job{{ID: 2, Name: "detection", Conclusion: "success"}}}}})
	if err == nil {
		t.Fatal("unread log reported as clean")
	}
}
