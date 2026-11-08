package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/httpguard"
	"github.com/VanSail-Opensource/X-Node/internal/update"
)

const repositoryRoot = "/repos/" + update.Repository
const qualityWorkflowID = 383872953
const maxAPIBytes = 8 << 20

type apiClient struct {
	origin string
	token  string
	http   *http.Client
}

func newAPIClient(token string) *apiClient {
	return &apiClient{origin: "https://api.github.com", token: token, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *apiClient) request(ctx context.Context, method, path string, body, out any) error {
	if !strings.HasPrefix(path, repositoryRoot) || strings.ContainsAny(path, "\r\n#") {
		return errors.New("invalid GitHub API operation")
	}
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return errors.New("invalid GitHub API request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(encoded))
	if err != nil {
		return errors.New("invalid GitHub API request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "X-Node-repository-setup")
	req.Header.Set("Content-Type", "application/json")
	response, err := httpguard.Do(c.http, req, httpguard.ExactOrigin)
	if err != nil {
		return fmt.Errorf("GitHub API %s %s: request failed", method, req.URL.EscapedPath())
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		status := apiStatusError{Status: response.StatusCode, Method: method, Path: req.URL.EscapedPath()}
		if response.StatusCode == http.StatusUnprocessableEntity {
			status.Details = validationIdentifiers(response.Body)
		}
		return status
	}
	if out == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if err != nil || len(raw) > maxAPIBytes || json.Unmarshal(raw, out) != nil {
		return fmt.Errorf("GitHub API %s %s: invalid response", method, req.URL.EscapedPath())
	}
	return nil
}

func isNotFound(err error) bool {
	var status apiStatusError
	return errors.As(err, &status) && status.Status == http.StatusNotFound
}
