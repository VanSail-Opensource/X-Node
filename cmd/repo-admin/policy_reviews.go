package main

import (
	"encoding/json"
	"errors"
	"sort"
)

func preservedReviews(raw json.RawMessage) (map[string]any, error) {
	var current map[string]json.RawMessage
	if len(raw) > 0 && json.Unmarshal(raw, &current) != nil {
		return nil, errors.New("invalid current review policy")
	}
	next := map[string]any{"required_approving_review_count": 1,
		"dismiss_stale_reviews": false, "require_code_owner_reviews": false, "require_last_push_approval": false,
		"dismissal_restrictions":         map[string][]string{"users": {}, "teams": {}, "apps": {}},
		"bypass_pull_request_allowances": map[string][]string{"users": {}, "teams": {}, "apps": {}}}
	for _, key := range []string{"dismiss_stale_reviews", "require_code_owner_reviews", "require_last_push_approval"} {
		if value := current[key]; len(value) > 0 {
			var enabled bool
			if json.Unmarshal(value, &enabled) != nil {
				return nil, errors.New("invalid current review policy")
			}
			next[key] = enabled
		}
	}
	if value := current["required_approving_review_count"]; len(value) > 0 {
		var count int
		if json.Unmarshal(value, &count) != nil || count < 0 || count > 6 {
			return nil, errors.New("invalid current review count")
		}
		next["required_approving_review_count"] = max(1, count)
	}
	// Ordinary collaborators require reviews; administrator bypass is controlled
	// separately by enforce_admins=false, not by additional PR bypass allowances.
	for _, key := range []string{"dismissal_restrictions"} {
		if value := current[key]; len(value) > 0 && string(value) != "null" {
			subjects, err := preservedSubjects(value)
			if err != nil {
				return nil, err
			}
			next[key] = subjects
		}
	}
	return next, nil
}

// Response objects use actors, whereas update requests require stable logins/slugs.
func preservedSubjects(raw json.RawMessage) (map[string][]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	// Read only the three actor arrays: response URL fields are not request fields.
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil, errors.New("invalid current protection actors")
	}
	next := map[string][]string{}
	for _, key := range []string{"users", "teams", "apps"} {
		next[key] = []string{}
		var actors []struct {
			Login string `json:"login"`
			Slug  string `json:"slug"`
		}
		if value := object[key]; len(value) > 0 && json.Unmarshal(value, &actors) != nil {
			return nil, errors.New("invalid current protection actors")
		}
		for _, actor := range actors {
			name := actor.Slug
			if key == "users" {
				name = actor.Login
			}
			if name == "" {
				return nil, errors.New("invalid current protection actor")
			}
			next[key] = append(next[key], name)
		}
		sort.Strings(next[key])
	}
	return next, nil
}
