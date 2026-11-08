package main

import (
	"context"
	"errors"
	"reflect"
	"sort"
)

const environmentPath = repositoryRoot + "/environments/release"

type branchPolicy struct {
	Protected bool `json:"protected_branches"`
	Custom    bool `json:"custom_branch_policies"`
}

type environmentPolicy struct {
	CanAdminsBypass *bool         `json:"can_admins_bypass"`
	BranchPolicy    *branchPolicy `json:"deployment_branch_policy"`
	Rules           []struct {
		Type        string `json:"type"`
		Wait        int    `json:"wait_timer"`
		PreventSelf bool   `json:"prevent_self_review"`
		Reviewers   []struct {
			Type     string `json:"type"`
			Reviewer struct {
				ID int64 `json:"id"`
			} `json:"reviewer"`
		} `json:"reviewers"`
	} `json:"protection_rules"`
}

type environmentReviewer struct {
	Type string `json:"type"`
	ID   int64  `json:"id"`
}

type environmentUpdate struct {
	Wait            int                   `json:"wait_timer"`
	PreventSelf     bool                  `json:"prevent_self_review"`
	Reviewers       []environmentReviewer `json:"reviewers"`
	CanAdminsBypass bool                  `json:"can_admins_bypass"`
	BranchPolicy    branchPolicy          `json:"deployment_branch_policy"`
}

type deploymentPolicy struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func preservedEnvironment(current environmentPolicy) (environmentUpdate, error) {
	body := environmentUpdate{Reviewers: []environmentReviewer{}, BranchPolicy: branchPolicy{Custom: true}}
	seen := map[string]bool{}
	for _, rule := range current.Rules {
		if seen[rule.Type] {
			return body, errors.New("duplicate existing environment protection")
		}
		seen[rule.Type] = true
		switch rule.Type {
		case "branch_policy":
		case "wait_timer":
			if rule.Wait < 0 || rule.Wait > 43200 {
				return body, errors.New("invalid existing environment timer")
			}
			body.Wait = rule.Wait
		case "required_reviewers":
			body.PreventSelf = rule.PreventSelf
			for _, reviewer := range rule.Reviewers {
				if reviewer.Type != "User" && reviewer.Type != "Team" || reviewer.Reviewer.ID <= 0 {
					return body, errors.New("unsupported existing environment reviewer")
				}
				body.Reviewers = append(body.Reviewers, environmentReviewer{Type: reviewer.Type, ID: reviewer.Reviewer.ID})
			}
		default:
			return body, errors.New("unsupported existing environment protection")
		}
	}
	if len(body.Reviewers) > 6 {
		return body, errors.New("invalid existing environment reviewer count")
	}
	sort.Slice(body.Reviewers, func(i, j int) bool {
		if body.Reviewers[i].Type != body.Reviewers[j].Type {
			return body.Reviewers[i].Type < body.Reviewers[j].Type
		}
		return body.Reviewers[i].ID < body.Reviewers[j].ID
	})
	return body, nil
}

func (c *apiClient) protectEnvironment(ctx context.Context) error {
	var current environmentPolicy
	if err := c.request(ctx, "GET", environmentPath, nil, &current); err != nil {
		return err
	}
	body, err := preservedEnvironment(current)
	if err != nil {
		return err
	}
	policies, err := c.deploymentPolicies(ctx)
	if err != nil {
		return err
	}
	for _, policy := range policies {
		if policy.ID <= 0 {
			return errors.New("invalid release deployment policy identity")
		}
		if !(policy.Name == "main" && policy.Type == "branch") && !(policy.Name == "v*" && policy.Type == "tag") {
			return errors.New("unexpected release deployment policy; existing policy preserved")
		}
	}
	if err := c.request(ctx, "PUT", environmentPath, body, nil); err != nil {
		return err
	}
	found := false
	for _, policy := range policies {
		if policy.Name == "main" && policy.Type == "branch" {
			found = true
			continue
		}
		if err := c.request(ctx, "DELETE", environmentPath+"/deployment-branch-policies/"+decimalID(policy.ID), nil, nil); err != nil {
			return err
		}
	}
	if !found {
		if err := c.request(ctx, "POST", environmentPath+"/deployment-branch-policies", map[string]string{"name": "main", "type": "branch"}, nil); err != nil {
			return err
		}
	}
	return c.verifyEnvironment(ctx, &body)
}

func (c *apiClient) verifyEnvironment(ctx context.Context, expected *environmentUpdate) error {
	var current environmentPolicy
	if err := c.request(ctx, "GET", environmentPath, nil, &current); err != nil {
		return err
	}
	if current.CanAdminsBypass == nil || *current.CanAdminsBypass || current.BranchPolicy == nil || current.BranchPolicy.Protected || !current.BranchPolicy.Custom {
		return errors.New("release environment verification failed")
	}
	if expected != nil {
		actual, err := preservedEnvironment(current)
		if err != nil || !reflect.DeepEqual(actual, *expected) {
			return errors.New("release reviewer protection preservation failed")
		}
	}
	policies, err := c.deploymentPolicies(ctx)
	if err != nil {
		return err
	}
	if len(policies) != 1 || policies[0].ID <= 0 || policies[0].Name != "main" || policies[0].Type != "branch" {
		return errors.New("release deployment branch verification failed")
	}
	return nil
}

func (c *apiClient) deploymentPolicies(ctx context.Context) ([]deploymentPolicy, error) {
	return listPolicies[deploymentPolicy](ctx, c, environmentPath+"/deployment-branch-policies", "branch_policies")
}
