// repo-admin configures and inspects this repository using Git Credential Manager.
// Credentials and private signing material are never printed.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/update"
	"golang.org/x/crypto/nacl/box"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
func run() error {
	keyPath := flag.String("key-file", "", "private release key file")
	runID := flag.Int64("run-id", 0, "workflow run ID")
	flag.Parse()
	if flag.NArg() != 1 {
		return errors.New("choose info, signing-secret, automerge, runs, release or workflow")
	}
	cmd := exec.Command("git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	credential, e := cmd.Output()
	if e != nil {
		return errors.New("GitHub credentials unavailable")
	}
	token := ""
	for _, line := range strings.Split(string(credential), "\n") {
		k, v, _ := strings.Cut(line, "=")
		if k == "password" {
			token = v
		}
	}
	if token == "" {
		return errors.New("GitHub token unavailable")
	}
	request := func(method, path string, body any, out any) error {
		b, _ := json.Marshal(body)
		req, e := http.NewRequest(method, "https://api.github.com"+path, bytes.NewReader(b))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "X-Node-repository-setup")
		req.Header.Set("Content-Type", "application/json")
		response, e := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if e != nil {
			return errors.New("GitHub API request failed")
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return errors.New("GitHub API status " + strconv.Itoa(response.StatusCode))
		}
		if out != nil {
			return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out)
		}
		return nil
	}
	root := "/repos/" + update.Repository
	switch flag.Arg(0) {
	case "info":
		var repo struct {
			FullName       string          `json:"full_name"`
			DefaultBranch  string          `json:"default_branch"`
			Permissions    map[string]bool `json:"permissions"`
			AllowAutoMerge bool            `json:"allow_auto_merge"`
		}
		if e = request("GET", root, nil, &repo); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(repo)
	case "signing-secret":
		if *keyPath == "" {
			return errors.New("key-file is required")
		}
		secret, e := os.ReadFile(*keyPath)
		if e != nil {
			return errors.New("signing key unavailable")
		}
		var public struct {
			KeyID string `json:"key_id"`
			Key   string `json:"key"`
		}
		if e = request("PUT", root+"/environments/release", map[string]any{"deployment_branch_policy": map[string]bool{"protected_branches": false, "custom_branch_policies": true}}, nil); e != nil {
			return e
		}
		var policies struct {
			Policies []struct {
				Name string `json:"name"`
			} `json:"branch_policies"`
		}
		if e = request("GET", root+"/environments/release/deployment-branch-policies", nil, &policies); e != nil {
			return e
		}
		found := false
		for _, p := range policies.Policies {
			if p.Name == "v*" {
				found = true
			}
		}
		if !found {
			if e = request("POST", root+"/environments/release/deployment-branch-policies", map[string]string{"name": "v*", "type": "tag"}, nil); e != nil {
				return e
			}
		}
		if e = request("GET", root+"/environments/release/secrets/public-key", nil, &public); e != nil {
			return e
		}
		decoded, e := base64.StdEncoding.DecodeString(public.Key)
		if e != nil || len(decoded) != 32 {
			return errors.New("invalid repository encryption key")
		}
		var recipient [32]byte
		copy(recipient[:], decoded)
		encrypted, e := box.SealAnonymous(nil, secret, &recipient, rand.Reader)
		if e != nil {
			return errors.New("signing key encryption failed")
		}
		if e = request("PUT", root+"/environments/release/secrets/RELEASE_MINISIGN_SECRET_KEY", map[string]string{"key_id": public.KeyID, "encrypted_value": base64.StdEncoding.EncodeToString(encrypted)}, nil); e != nil {
			return e
		}
		if e = request("DELETE", root+"/actions/secrets/RELEASE_MINISIGN_SECRET_KEY", nil, nil); e != nil {
			return e
		}
		fmt.Println("Protected release signing secret configured.")
		return nil
	case "automerge":
		if e = request("PATCH", root, map[string]bool{"allow_auto_merge": true}, nil); e != nil {
			return e
		}
		fmt.Println("Repository auto-merge enabled.")
		return nil
	case "runs":
		var response struct {
			Runs []struct {
				ID         int64  `json:"id"`
				Name       string `json:"name"`
				SHA        string `json:"head_sha"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
				URL        string `json:"html_url"`
				Created    string `json:"created_at"`
				Updated    string `json:"updated_at"`
			} `json:"workflow_runs"`
		}
		if e = request("GET", root+"/actions/runs?per_page=12", nil, &response); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(response.Runs)
	case "jobs":
		if *runID == 0 {
			return errors.New("run-id is required")
		}
		var result struct {
			Jobs []struct {
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
			} `json:"jobs"`
		}
		if e = request("GET", root+fmt.Sprintf("/actions/runs/%d/jobs?per_page=100", *runID), nil, &result); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result.Jobs)
	case "protect":
		checks := []string{"Tests and schemas", "Debian binary amd64", "Debian binary arm64", "Vulnerability scan", "Debian 13 host integration"}
		body := map[string]any{"required_status_checks": map[string]any{"strict": true, "contexts": checks}, "enforce_admins": false, "required_pull_request_reviews": nil, "restrictions": nil, "allow_force_pushes": false, "allow_deletions": false}
		if e = request("PUT", root+"/branches/main/protection", body, nil); e != nil {
			return e
		}
		fmt.Println("Main quality gates configured.")
		return nil
	case "releases":
		var releases []struct {
			Tag    string `json:"tag_name"`
			URL    string `json:"html_url"`
			Draft  bool   `json:"draft"`
			Assets []struct {
				Name string `json:"name"`
				Size int64  `json:"size"`
				URL  string `json:"browser_download_url"`
			} `json:"assets"`
		}
		if e = request("GET", root+"/releases?per_page=5", nil, &releases); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(releases)
	default:
		return errors.New("unsupported repository operation")
	}
}
