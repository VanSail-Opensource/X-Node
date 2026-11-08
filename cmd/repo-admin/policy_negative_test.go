package main

import (
	"context"
	"io"
	"testing"
)

func TestDispatchRejectsUnsafeObservedProtection(t *testing.T) {
	for name, change := range map[string]func(*policyFixture){
		"wrong check provider": func(f *policyFixture) {
			checks := f.main["required_status_checks"].(map[string]any)["checks"].([]any)
			checks[0].(map[string]any)["app_id"] = float64(7)
		},
		"admin direct push disabled": func(f *policyFixture) { f.main["enforce_admins"] = map[string]bool{"enabled": true} },
		"force enabled":              func(f *policyFixture) { f.main["allow_force_pushes"] = map[string]bool{"enabled": true} },
		"review bypass": func(f *policyFixture) {
			f.main["required_pull_request_reviews"].(map[string]any)["bypass_pull_request_allowances"] = map[string]any{"users": []any{map[string]string{"login": "fixture-user"}}}
		},
		"environment admin bypass": func(f *policyFixture) { f.environment["can_admins_bypass"] = true },
		"tag instead of branch":    func(f *policyFixture) { f.deployments[0]["type"] = "tag" },
	} {
		t.Run(name, func(t *testing.T) {
			api, fixture := newPolicyFixture(t)
			if err := api.protectRelease(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			change(fixture)
			fixture.mu.Unlock()
			if err := execute(context.Background(), api, "dispatch-release", options{version: "v2.0.20", runID: 123}, io.Discard); err == nil {
				t.Fatal("unsafe observed settings permitted release dispatch")
			}
			if fixture.writeCount("POST", "/actions/workflows/release.yml/dispatches") != 0 {
				t.Fatal("rejected dispatch still reached GitHub")
			}
		})
	}
}

func TestMainReadbackMustPreserveExistingStrongerReviewCount(t *testing.T) {
	api, fixture := newPolicyFixture(t)
	if err := api.protectRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.main["required_pull_request_reviews"].(map[string]any)["required_approving_review_count"] = float64(2)
	fixture.ignore = "main-review"
	fixture.mu.Unlock()
	if err := api.protectMain(context.Background()); err == nil {
		t.Fatal("2xx response concealed a weakened existing review requirement")
	}
}
