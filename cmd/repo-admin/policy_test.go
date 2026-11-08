package main

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"testing"
)

func TestProtectReleasePreservesReviewersAndIsIdempotent(t *testing.T) {
	api, fixture := newPolicyFixture(t)
	var original environmentPolicy
	_ = json.Unmarshal(mustJSON(fixture.environment), &original)
	want, err := preservedEnvironment(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"protect-release", "protect"} {
		if err := execute(context.Background(), api, operation, options{}, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if err := api.verifyEnvironment(context.Background(), &want); err != nil {
		t.Fatal(err)
	}
	if fixture.writeCount("POST", "/rulesets") != 1 || fixture.writeCount("POST", "/environments/release/deployment-branch-policies") != 1 || fixture.writeCount("DELETE", "/environments/release/deployment-branch-policies/1") != 1 {
		t.Fatal("reapplying policy duplicated managed rules or retained the legacy tag rule")
	}
	for _, write := range fixture.snapshot().writes {
		if write == "PUT /environments/release/secrets/RELEASE_MINISIGN_SECRET_KEY" {
			t.Fatal("policy operation uploaded a signing key")
		}
	}
}

func TestProtectionRequiresObservedPostconditions(t *testing.T) {
	for _, ignored := range []string{"main", "environment", "tags"} {
		t.Run(ignored, func(t *testing.T) {
			api, fixture := newPolicyFixture(t)
			fixture.ignore = ignored
			if err := api.protectRelease(context.Background()); err == nil {
				t.Fatal("successful HTTP response hid unapplied protection")
			}
		})
	}
}

func TestUnexpectedEnvironmentPolicyIsPreserved(t *testing.T) {
	api, fixture := newPolicyFixture(t)
	fixture.deployments = append(fixture.deployments, map[string]any{"id": 3, "name": "maintenance", "type": "branch"})
	before := fixture.snapshot().deployments
	if err := api.protectRelease(context.Background()); err == nil {
		t.Fatal("unexpected policy drift was silently overwritten")
	}
	if fixture.snapshot().deployments != before || fixture.writeCount("PUT", "/environments/release") != 0 {
		t.Fatal("unrelated policy was changed")
	}
}

func TestExistingMainChecksAndReviewRestrictionsArePreserved(t *testing.T) {
	current := map[string]json.RawMessage{
		"required_status_checks":        json.RawMessage(`{"strict":false,"contexts":["External build"],"checks":[{"context":"External build","app_id":987}]}`),
		"required_pull_request_reviews": json.RawMessage(`{"required_approving_review_count":2,"dismiss_stale_reviews":true,"require_code_owner_reviews":true,"require_last_push_approval":true,"dismissal_restrictions":{"url":"ignored","users":[{"login":"owner"}],"teams":[{"slug":"reviewers"}],"apps":[]}}`),
		"restrictions":                  json.RawMessage(`{"users":[{"login":"owner"}],"teams":[],"apps":[]}`),
		"required_linear_history":       json.RawMessage(`{"enabled":true}`),
	}
	body, err := mainPolicyBody(current)
	if err != nil {
		t.Fatal(err)
	}
	status := body["required_status_checks"].(statusUpdate)
	if !status.Strict || len(status.Checks) != len(qualityChecks)+1 || status.Checks[len(qualityChecks)] != (requiredCheck{Context: "External build", AppID: 987}) {
		t.Fatal("existing check or app binding was lost")
	}
	reviews := body["required_pull_request_reviews"].(map[string]any)
	if reviews["required_approving_review_count"] != 2 || reviews["dismiss_stale_reviews"] != true || reviews["require_code_owner_reviews"] != true || reviews["require_last_push_approval"] != true || body["required_linear_history"] != true {
		t.Fatal("existing review restrictions were weakened")
	}
	actors := reviews["dismissal_restrictions"].(map[string][]string)
	if !reflect.DeepEqual(actors["users"], []string{"owner"}) || !reflect.DeepEqual(actors["teams"], []string{"reviewers"}) {
		t.Fatal("review actors were not converted into request identities")
	}
}

func TestTagVerificationRejectsBypassCreationAndMissingEvidence(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(policy map[string]any) {
			policy["bypass_actors"] = []any{map[string]any{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}}
		},
		func(policy map[string]any) { delete(policy, "bypass_actors") },
		func(policy map[string]any) {
			policy["rules"] = []map[string]string{{"type": "update"}, {"type": "creation"}}
		},
		func(policy map[string]any) {
			policy["conditions"] = map[string]any{"ref_name": map[string]any{"include": []string{"refs/tags/v*"}, "exclude": []string{"refs/tags/v1*"}}}
		},
	} {
		policy := desiredTagRuleset()
		change(policy)
		var actual tagRuleset
		if json.Unmarshal(mustJSON(policy), &actual) != nil || validTagRuleset(actual) {
			t.Fatal("unsafe tag policy accepted")
		}
	}
}
