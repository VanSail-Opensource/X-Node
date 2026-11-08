package sessions

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

// rekeyUsers runs under the registry lock before ordinary reconciliation. Lease
// counters retain their original period/sample keys until the sampler drains
// them, so an identity change cannot replay cumulative bytes as fresh traffic.
func (r *Registry) rekeyUsers(replacements map[int]int) {
	targets := map[*userState]int{}
	moved := map[int]*userState{}
	for previous, next := range replacements {
		old := r.users[previous]
		if old == nil {
			continue
		}
		targets[old], moved[next] = next, old
	}
	for id, old := range r.users {
		if _, moving := targets[old]; moving {
			delete(r.users, id)
		}
	}
	for id, old := range moved {
		previous := old.policy.ID
		old.policy.ID, old.policy.ReplacesID = id, previous
		r.users[id] = old
		if until := r.bans[previous]; !until.IsZero() {
			if until.After(r.bans[id]) {
				r.bans[id] = until
			}
			delete(r.bans, previous)
		}
	}
	for _, lease := range r.inflight {
		if id, moving := targets[lease.user]; moving {
			lease.Info.UserID = id
		}
	}
	for _, lease := range r.connections {
		if id, moving := targets[lease.user]; moving {
			lease.Info.UserID = id
		}
	}
}

// Retain only verified aliases or an exact replay of an existing alias. Merely
// declaring replaces_id for a new unrelated principal is never live proof.
func (r *Registry) reconcileAliases(users []protocol.User, replacements map[int]int) {
	aliases := map[int]int{}
	for previous, next := range replacements {
		aliases[previous] = next
	}
	for _, policy := range users {
		previous := policy.ReplacesID
		current := r.users[policy.ID]
		if previous > 0 && r.identityAliases[previous] == policy.ID && current != nil && sameIdentity(current.policy, policy) {
			aliases[previous] = policy.ID
		}
	}
	r.identityAliases = aliases
}

// A stale mux transport is accepted only when its complete credential-bound
// identity still matches the replacement. A numeric collision never suffices.
func (r *Registry) rekeyIdentity(old int, identity, tag string) int {
	id := r.identityAliases[old]
	if user := r.users[id]; user != nil {
		if _, valid := user.identities.lookup(identity, tag); valid {
			return id
		}
	}
	return 0
}
