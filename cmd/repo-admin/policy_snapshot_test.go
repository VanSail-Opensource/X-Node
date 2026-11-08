package main

import "encoding/json"

type policySnapshot struct {
	writes      []string
	dispatch    map[string]any
	secretBody  map[string]string
	deployments string
}

func (f *policyFixture) snapshot() policySnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	copy := policySnapshot{writes: append([]string{}, f.writes...), deployments: string(mustJSON(f.deployments))}
	_ = json.Unmarshal(mustJSON(f.dispatch), &copy.dispatch)
	_ = json.Unmarshal(mustJSON(f.secretBody), &copy.secretBody)
	return copy
}
