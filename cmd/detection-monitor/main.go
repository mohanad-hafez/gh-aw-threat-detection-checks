package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/github/gh-aw-threat-detection/internal/monitor"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func checkpoint(path string, receipt map[string]any) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(path+".tmp", append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func run() error {
	if os.Getenv("GITHUB_REPOSITORY") != monitor.Target {
		return fmt.Errorf("run only in the owned experimental repository")
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GitHub runtime token is missing")
	}
	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" || strings.Trim(runID, "0123456789") != "" {
		return fmt.Errorf("valid Actions run identity is required")
	}
	path := "monitor-receipt.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return fmt.Errorf("receipt already exists or cannot be inspected; review it before another execution")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	c := monitor.NewClient(token)
	input, evidence, err := c.Collect(ctx, time.Now().UTC(), "https://github.com/"+monitor.Target+"/actions/runs/"+runID)
	receipt := map[string]any{"status": "collected", "evidence": evidence, "source": monitor.Source, "target": monitor.Target, "model_calls": 0}
	fail := func(err error) error {
		receipt["status"] = "inspection_required"
		receipt["error"] = err.Error()
		if saveErr := checkpoint(path, receipt); saveErr != nil {
			return saveErr
		}
		return err
	}
	if err != nil {
		return fail(err)
	}
	output, err := monitor.Plan(input)
	if err != nil {
		return fail(err)
	}
	// Never serialize input: it contains transient source log tails.
	receipt["plan"] = output
	if len(output.Actions) == 0 {
		receipt["status"] = "bounded_source_noop"
		if evidence.ReadErrors > 0 {
			receipt["status"] = "incomplete_reads"
		}
		return checkpoint(path, receipt)
	}
	action := output.Actions[0]
	title := action["title"].(string)
	body := action["body"].(string)
	if evidence.ReadErrors > 0 {
		body = strings.Replace(body, "in the last 24 hours.", fmt.Sprintf("observed in the last 24 hours; %d reads were incomplete.", evidence.ReadErrors), 1)
	}
	payload := map[string]any{"title": "[detection-failures] " + title, "body": body, "labels": []string{"automation", "detection-monitor"}}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fail(err)
	}
	receipt["request_sha256"] = fmt.Sprintf("%x", sha256.Sum256(encoded))
	receipt["status"] = "delivery_pending"
	if err = checkpoint(path, receipt); err != nil {
		return err
	}
	issue, err := c.CreateIssue(ctx, title, body)
	if err != nil {
		receipt["status"] = "delivery_uncertain"
		receipt["error"] = err.Error()
		if saveErr := checkpoint(path, receipt); saveErr != nil {
			return saveErr
		}
		return err
	}
	receipt["issue"] = issue
	receipt["status"] = "created_readback_pending"
	if err = checkpoint(path, receipt); err != nil {
		return err
	}
	readback, err := c.ReadIssue(ctx, issue.Number)
	if err != nil {
		return fail(err)
	}
	receipt["readback"] = readback
	if readback.Title != payload["title"] || readback.Body != body {
		return fail(fmt.Errorf("created issue readback differs from the requested report"))
	}
	receipt["status"] = "created_verified"
	receipt["github_api_requests"] = c.Requests
	return checkpoint(path, receipt)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
