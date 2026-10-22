package sessions

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

// rekeyUsers runs under the registry lock before ordinary reconciliation. Lease
// counters retain their original period/sample keys until the sampler drains
// them, so an identity change cannot replay cumulative bytes as fresh traffic.
func (r *Registry) rekeyUsers(users []protocol.User) {
	targets := map[*userState]int{}
	moved := map[int]*userState{}
	for _, policy := range users {
		if policy.ReplacesID == 0 {
			continue
		}
		old := r.users[policy.ReplacesID]
		if old == nil || old.policy.ID != policy.ReplacesID || old.policy.UUID != policy.UUID || old.policy.AccountingPeriod != policy.AccountingPeriod {
			continue
		}
		candidate := old.policy
		candidate.ID, candidate.ReplacesID = policy.ID, policy.ReplacesID
		if !sameIdentity(candidate, policy) {
			continue
		}
		targets[old], moved[policy.ID] = policy.ID, old
	}
	if len(moved) == 0 {
		return
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
			r.bans[id] = until
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

// A stale mux transport is accepted only when its complete credential-bound
// identity still matches the replacement. A numeric collision never suffices.
func (r *Registry) rekeyIdentity(old int, identity, tag string) int {
	id := r.identityAliases[old]
	if user := r.users[id]; user != nil && r.validIdentity(user.policy, identity, tag) {
		return id
	}
	return 0
}
