package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type policyFixture struct {
	mu          sync.Mutex
	main        map[string]any
	environment map[string]any
	deployments []map[string]any
	tags        map[string]any
	writes      []string
	dispatch    map[string]any
	ignore      string
	secretBody  map[string]string
}

func newPolicyFixture(t *testing.T) (*apiClient, *policyFixture) {
	t.Helper()
	f := &policyFixture{environment: map[string]any{
		"can_admins_bypass":        true,
		"deployment_branch_policy": map[string]bool{"protected_branches": false, "custom_branch_policies": true},
		"protection_rules": []any{
			map[string]any{"type": "branch_policy"},
			map[string]any{"type": "wait_timer", "wait_timer": 30},
			map[string]any{"type": "required_reviewers", "prevent_self_review": true, "reviewers": []any{
				map[string]any{"type": "User", "reviewer": map[string]int64{"id": 7}},
				map[string]any{"type": "Team", "reviewer": map[string]int64{"id": 8}},
			}},
		},
	}, deployments: []map[string]any{{"id": 1, "name": "v*", "type": "tag"}}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	return &apiClient{origin: server.URL, token: "fixture-api-token", http: server.Client()}, f
}

func (f *policyFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, repositoryRoot)
	if r.Method != "GET" {
		f.writes = append(f.writes, r.Method+" "+path)
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer fixture-api-token" {
		w.WriteHeader(401)
		return
	}
	switch {
	case path == "/branches/main/protection":
		f.serveMain(w, r)
	case path == "/environments/release":
		if r.Method == "PUT" {
			var body environmentUpdate
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			if f.ignore != "environment" {
				f.environment = environmentResponse(body)
			}
		}
		_ = json.NewEncoder(w).Encode(f.environment)
	case path == "/environments/release/deployment-branch-policies":
		if r.Method == "POST" {
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			body["id"] = 2
			f.deployments = append(f.deployments, body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(f.deployments), "branch_policies": f.deployments})
	case strings.HasPrefix(path, "/environments/release/deployment-branch-policies/") && r.Method == "DELETE":
		id := strings.TrimPrefix(path, "/environments/release/deployment-branch-policies/")
		kept := []map[string]any{}
		for _, policy := range f.deployments {
			if strings.TrimSpace(string(mustJSON(policy["id"]))) != id {
				kept = append(kept, policy)
			}
		}
		f.deployments = kept
		w.WriteHeader(204)
	case path == "/rulesets" && r.Method == "GET":
		if f.tags == nil {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 77, "name": tagRulesetName}})
	case path == "/rulesets" && r.Method == "POST" || path == "/rulesets/77" && r.Method == "PUT":
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		body["id"] = 77
		if f.ignore != "tags" {
			f.tags = body
		}
		_ = json.NewEncoder(w).Encode(body)
	case path == "/rulesets/77" && r.Method == "GET":
		_ = json.NewEncoder(w).Encode(f.tags)
	case path == "/actions/workflows/release.yml/dispatches" && r.Method == "POST":
		_ = json.NewDecoder(r.Body).Decode(&f.dispatch)
		w.WriteHeader(204)
	case path == "/environments/release/secrets/public-key" && r.Method == "GET":
		publicKey := make([]byte, 32)
		publicKey[0] = 9 // Curve25519's public base point is fixture material only.
		_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "fixture-public-key", "key": base64.StdEncoding.EncodeToString(publicKey)})
	case path == "/environments/release/secrets/RELEASE_MINISIGN_SECRET_KEY" && r.Method == "PUT":
		_ = json.NewDecoder(r.Body).Decode(&f.secretBody)
		w.WriteHeader(201)
	case path == "/actions/secrets/RELEASE_MINISIGN_SECRET_KEY" && r.Method == "DELETE":
		w.WriteHeader(404) // An already absent legacy copy is an idempotent success.
	default:
		w.WriteHeader(404)
	}
}

func environmentResponse(body environmentUpdate) map[string]any {
	rules := []any{map[string]any{"type": "branch_policy"}}
	if body.Wait > 0 {
		rules = append(rules, map[string]any{"type": "wait_timer", "wait_timer": body.Wait})
	}
	if len(body.Reviewers) > 0 {
		reviewers := []any{}
		for _, reviewer := range body.Reviewers {
			reviewers = append(reviewers, map[string]any{"type": reviewer.Type, "reviewer": map[string]int64{"id": reviewer.ID}})
		}
		rules = append(rules, map[string]any{"type": "required_reviewers", "prevent_self_review": body.PreventSelf, "reviewers": reviewers})
	}
	return map[string]any{"can_admins_bypass": body.CanAdminsBypass, "deployment_branch_policy": body.BranchPolicy, "protection_rules": rules}
}

func mustJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }

func (f *policyFixture) writeCount(method, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, write := range f.writes {
		if write == method+" "+path {
			count++
		}
	}
	return count
}
