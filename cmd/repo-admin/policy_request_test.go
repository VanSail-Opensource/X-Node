package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestMainUpdateUsesChecksOnly(t *testing.T) {
	current := map[string]json.RawMessage{"required_status_checks": json.RawMessage(`{"strict":true,"contexts":["External build","Legacy context"],"checks":[{"context":"External build","app_id":987}]}`)}
	body, err := mainPolicyBody(current)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Status map[string]json.RawMessage `json:"required_status_checks"`
	}
	if json.Unmarshal(mustJSON(body), &request) != nil {
		t.Fatal("invalid update request JSON")
	}
	if _, exists := request.Status["contexts"]; exists {
		t.Fatal("response-only contexts were copied into a checks update")
	}
	var checks []requiredCheck
	if json.Unmarshal(request.Status["checks"], &checks) != nil || len(checks) != len(qualityChecks)+2 {
		t.Fatal("checks update lost existing legacy contexts")
	}
	for _, want := range []requiredCheck{{Context: "External build", AppID: 987}, {Context: "Legacy context", AppID: -1}} {
		found := false
		for _, check := range checks {
			found = found || check == want
		}
		if !found {
			t.Fatal("existing check identity or legacy context was changed")
		}
	}
}

func TestMockGitHubRejectsSimultaneousChecksAndContexts(t *testing.T) {
	api, _ := newPolicyFixture(t)
	body := map[string]any{"required_status_checks": map[string]any{"strict": true, "contexts": []string{}, "checks": []requiredCheck{{Context: qualityChecks[0], AppID: actionsAppID}}}}
	err := api.request(context.Background(), "PUT", repositoryRoot+"/branches/main/protection", body, nil)
	var status apiStatusError
	if !errors.As(err, &status) || status.Status != 422 {
		t.Fatal("mock accepted the request rejected by GitHub's oneOf contract")
	}
}
