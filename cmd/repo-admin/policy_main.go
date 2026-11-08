package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
)

const actionsAppID = 15368

var qualityChecks = []string{
	"Tests and schemas", "Debian binary amd64", "Debian binary arm64",
	"Vulnerability scan", "Host debian / nftables-on", "Host debian / nftables-off",
}

type requiredCheck struct {
	Context string `json:"context"`
	AppID   int    `json:"app_id"`
}

type statusPolicy struct {
	Strict   bool            `json:"strict"`
	Contexts []string        `json:"contexts"`
	Checks   []requiredCheck `json:"checks"`
}

// GitHub responses contain both fields, but update requests allow only one.
// Keep the request shape separate so legacy response contexts cannot leak back.
type statusUpdate struct {
	Strict bool            `json:"strict"`
	Checks []requiredCheck `json:"checks"`
}

type enabledPolicy struct {
	Enabled *bool `json:"enabled"`
}

type mainPolicy struct {
	Status *statusPolicy `json:"required_status_checks"`
	Admins enabledPolicy `json:"enforce_admins"`
	Force  enabledPolicy `json:"allow_force_pushes"`
	Delete enabledPolicy `json:"allow_deletions"`
	Review *struct {
		Count  int `json:"required_approving_review_count"`
		Bypass struct {
			Users []json.RawMessage `json:"users"`
			Teams []json.RawMessage `json:"teams"`
			Apps  []json.RawMessage `json:"apps"`
		} `json:"bypass_pull_request_allowances"`
	} `json:"required_pull_request_reviews"`
}

func (c *apiClient) protectMain(ctx context.Context) error {
	var current map[string]json.RawMessage
	if err := c.request(ctx, "GET", repositoryRoot+"/branches/main/protection", nil, &current); err != nil && !isNotFound(err) {
		return err
	}
	body, err := mainPolicyBody(current)
	if err != nil {
		return err
	}
	if err := c.request(ctx, "PUT", repositoryRoot+"/branches/main/protection", body, nil); err != nil {
		return err
	}
	if err := c.verifyMainPreservation(ctx, body); err != nil {
		return err
	}
	return c.verifyMain(ctx)
}

func (c *apiClient) verifyMain(ctx context.Context) error {
	var policy mainPolicy
	if err := c.request(ctx, "GET", repositoryRoot+"/branches/main/protection", nil, &policy); err != nil {
		return err
	}
	if policy.Status == nil || !policy.Status.Strict || policy.Review == nil || policy.Review.Count < 1 ||
		!explicitlyDisabled(policy.Admins) || !explicitlyDisabled(policy.Force) || !explicitlyDisabled(policy.Delete) {
		return errors.New("main protection verification failed")
	}
	if len(policy.Review.Bypass.Users)+len(policy.Review.Bypass.Teams)+len(policy.Review.Bypass.Apps) != 0 {
		return errors.New("main review bypass verification failed")
	}
	for _, name := range qualityChecks {
		found := false
		for _, check := range policy.Status.Checks {
			found = found || check.Context == name && check.AppID == actionsAppID
		}
		if !found {
			return errors.New("main required check verification failed")
		}
	}
	return nil
}

func explicitlyDisabled(policy enabledPolicy) bool { return policy.Enabled != nil && !*policy.Enabled }

func mainPolicyBody(current map[string]json.RawMessage) (map[string]any, error) {
	var status statusPolicy
	if raw := current["required_status_checks"]; len(raw) > 0 && json.Unmarshal(raw, &status) != nil {
		return nil, errors.New("invalid current status checks")
	}
	checks := []requiredCheck{}
	seen := map[string]bool{}
	for _, name := range qualityChecks {
		checks = append(checks, requiredCheck{Context: name, AppID: actionsAppID})
		seen[name] = true
	}
	for _, check := range status.Checks {
		if !seen[check.Context] {
			if check.Context == "" {
				return nil, errors.New("invalid current status check")
			}
			if check.AppID == 0 {
				check.AppID = -1
			}
			checks = append(checks, check)
			seen[check.Context] = true
		}
	}
	for _, name := range status.Contexts {
		if !seen[name] {
			if name == "" {
				return nil, errors.New("invalid current status check")
			}
			checks = append(checks, requiredCheck{Context: name, AppID: -1})
			seen[name] = true
		}
	}
	reviews, err := preservedReviews(current["required_pull_request_reviews"])
	if err != nil {
		return nil, err
	}
	restrictions, err := preservedSubjects(current["restrictions"])
	if err != nil {
		return nil, err
	}
	body := map[string]any{"required_status_checks": statusUpdate{Strict: true, Checks: checks},
		"enforce_admins": false, "required_pull_request_reviews": reviews, "restrictions": restrictions,
		"allow_force_pushes": false, "allow_deletions": false}
	for _, key := range []string{"required_linear_history", "required_conversation_resolution", "lock_branch", "allow_fork_syncing", "block_creations"} {
		if raw := current[key]; len(raw) > 0 && string(raw) != "null" {
			var policy enabledPolicy
			if json.Unmarshal(raw, &policy) != nil || policy.Enabled == nil {
				return nil, errors.New("invalid current branch protection")
			}
			body[key] = *policy.Enabled
		}
	}
	return body, nil
}

func (c *apiClient) verifyMainPreservation(ctx context.Context, expected map[string]any) error {
	var current map[string]json.RawMessage
	if err := c.request(ctx, "GET", repositoryRoot+"/branches/main/protection", nil, &current); err != nil {
		return err
	}
	actual, err := mainPolicyBody(current)
	if err != nil {
		return err
	}
	for _, key := range []string{"required_pull_request_reviews", "restrictions", "required_linear_history", "required_conversation_resolution", "lock_branch", "allow_fork_syncing", "block_creations"} {
		if want, exists := expected[key]; exists && !reflect.DeepEqual(actual[key], want) {
			return errors.New("existing main protection preservation failed")
		}
	}
	observed := actual["required_status_checks"].(statusUpdate).Checks
	for _, want := range expected["required_status_checks"].(statusUpdate).Checks {
		found := false
		for _, got := range observed {
			found = found || got == want
		}
		if !found {
			return errors.New("existing main check preservation failed")
		}
	}
	return nil
}
