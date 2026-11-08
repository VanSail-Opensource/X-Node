package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func (c *apiClient) observe(ctx context.Context, operation string, opts options, out io.Writer) error {
	var result any
	var path string
	switch operation {
	case "info":
		result = &struct {
			FullName       string          `json:"full_name"`
			DefaultBranch  string          `json:"default_branch"`
			Permissions    map[string]bool `json:"permissions"`
			AllowAutoMerge bool            `json:"allow_auto_merge"`
		}{}
	case "runs":
		var response struct {
			Runs []workflowRun `json:"workflow_runs"`
		}
		if err := c.request(ctx, "GET", repositoryRoot+"/actions/runs?per_page=12", nil, &response); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(response.Runs)
	case "jobs":
		if opts.runID <= 0 {
			return errors.New("positive run-id is required")
		}
		var response struct {
			Jobs []workflowJob `json:"jobs"`
		}
		if err := c.request(ctx, "GET", repositoryRoot+fmt.Sprintf("/actions/runs/%d/jobs?per_page=100", opts.runID), nil, &response); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(response.Jobs)
	case "release", "releases":
		path = "/releases?per_page=5"
		result = &[]release{}
	case "workflow":
		path = fmt.Sprintf("/actions/workflows/%d", qualityWorkflowID)
		result = &struct {
			ID    int64  `json:"id"`
			Name  string `json:"name"`
			Path  string `json:"path"`
			State string `json:"state"`
			URL   string `json:"html_url"`
		}{}
	default:
		return errors.New("unsupported repository operation")
	}
	if err := c.request(ctx, "GET", repositoryRoot+path, nil, result); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

type workflowRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	SHA        string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	URL        string `json:"html_url"`
	Created    string `json:"created_at"`
	Updated    string `json:"updated_at"`
}

type workflowJob struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Started    string `json:"started_at"`
	Completed  string `json:"completed_at"`
	Steps      []struct {
		Name       string `json:"name"`
		Conclusion string `json:"conclusion"`
	} `json:"steps"`
}

type release struct {
	Tag    string `json:"tag_name"`
	URL    string `json:"html_url"`
	Draft  bool   `json:"draft"`
	Assets []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}
