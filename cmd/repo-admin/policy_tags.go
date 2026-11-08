package main

import (
	"context"
	"encoding/json"
	"errors"
)

const tagRulesetName = "Immutable release tags"

type tagRuleset struct {
	ID          int64              `json:"id,omitempty"`
	Name        string             `json:"name"`
	Target      string             `json:"target"`
	Enforcement string             `json:"enforcement"`
	Bypass      *[]json.RawMessage `json:"bypass_actors"`
	Conditions  struct {
		RefName struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		} `json:"ref_name"`
	} `json:"conditions"`
	Rules []struct {
		Type string `json:"type"`
	} `json:"rules"`
}

func desiredTagRuleset() map[string]any {
	return map[string]any{"name": tagRulesetName, "target": "tag", "enforcement": "active", "bypass_actors": []any{},
		"conditions": map[string]any{"ref_name": map[string]any{"include": []string{"refs/tags/v*"}, "exclude": []string{}}},
		"rules":      []map[string]string{{"type": "update"}, {"type": "deletion"}}}
}

func (c *apiClient) managedTagRuleset(ctx context.Context) (tagRuleset, bool, error) {
	rulesets, err := listPolicies[tagRuleset](ctx, c, repositoryRoot+"/rulesets?includes_parents=false", "")
	if err != nil {
		return tagRuleset{}, false, err
	}
	var found tagRuleset
	for _, ruleset := range rulesets {
		if ruleset.Name == tagRulesetName {
			if found.ID != 0 || ruleset.ID <= 0 {
				return found, false, errors.New("ambiguous managed tag ruleset")
			}
			found = ruleset
		}
	}
	if found.ID == 0 {
		return found, false, nil
	}
	var detail tagRuleset
	if err := c.request(ctx, "GET", repositoryRoot+"/rulesets/"+decimalID(found.ID), nil, &detail); err != nil {
		return detail, false, err
	}
	if detail.ID != found.ID || detail.Name != tagRulesetName || detail.Target != "tag" {
		return detail, false, errors.New("managed tag ruleset identity changed")
	}
	return detail, true, nil
}

func (c *apiClient) protectTags(ctx context.Context) error {
	current, exists, err := c.managedTagRuleset(ctx)
	if err != nil {
		return err
	}
	if exists && validTagRuleset(current) {
		return c.verifyTags(ctx)
	}
	method, path := "POST", repositoryRoot+"/rulesets"
	if exists {
		method, path = "PUT", path+"/"+decimalID(current.ID)
	}
	if err := c.request(ctx, method, path, desiredTagRuleset(), nil); err != nil {
		return err
	}
	return c.verifyTags(ctx)
}

func (c *apiClient) verifyTags(ctx context.Context) error {
	current, exists, err := c.managedTagRuleset(ctx)
	if err != nil {
		return err
	}
	if !exists || !validTagRuleset(current) {
		return errors.New("immutable release tag verification failed")
	}
	return nil
}

func validTagRuleset(policy tagRuleset) bool {
	refs := policy.Conditions.RefName
	if policy.Name != tagRulesetName || policy.Target != "tag" || policy.Enforcement != "active" || policy.Bypass == nil || len(*policy.Bypass) != 0 ||
		len(refs.Include) != 1 || refs.Include[0] != "refs/tags/v*" || len(refs.Exclude) != 0 || len(policy.Rules) != 2 {
		return false
	}
	update, deletion := false, false
	for _, rule := range policy.Rules {
		switch rule.Type {
		case "update":
			update = true
		case "deletion":
			deletion = true
		default:
			return false
		}
	}
	return update && deletion
}
