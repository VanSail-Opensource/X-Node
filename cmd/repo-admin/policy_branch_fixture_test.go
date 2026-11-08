package main

import (
	"encoding/json"
	"net/http"
)

// Called while the fixture lock is held. Match the API's asymmetric contract:
// requests select checks OR contexts, while responses publish both views.
func (f *policyFixture) serveMain(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" {
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		status, ok := body["required_status_checks"].(map[string]any)
		if !ok {
			w.WriteHeader(422)
			return
		}
		_, contexts := status["contexts"]
		_, checks := status["checks"]
		if contexts && checks {
			w.WriteHeader(422)
			_, _ = w.Write([]byte(`{"message":"Invalid request.","errors":["More than one subschema in oneOf matched."]}`))
			return
		}
		if f.ignore != "main" {
			for _, key := range []string{"enforce_admins", "allow_force_pushes", "allow_deletions", "required_linear_history", "required_conversation_resolution", "lock_branch", "allow_fork_syncing", "block_creations"} {
				if value, exists := body[key]; exists {
					body[key] = map[string]any{"enabled": value}
				}
			}
			if f.ignore == "main-review" {
				body["required_pull_request_reviews"].(map[string]any)["required_approving_review_count"] = float64(1)
			}
			if rawChecks, ok := status["checks"].([]any); ok {
				responseContexts := []string{}
				for _, check := range rawChecks {
					responseContexts = append(responseContexts, check.(map[string]any)["context"].(string))
				}
				status["contexts"] = responseContexts
			}
			f.main = body
		}
	}
	if f.main == nil {
		w.WriteHeader(404)
		return
	}
	_ = json.NewEncoder(w).Encode(f.main)
}
