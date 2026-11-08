package sessions

import (
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// SetUsers is the direct in-memory policy entry point. Production publishes the
// durable authorization and block snapshot together through ApplyAuthorization.
func (r *Registry) SetUsers(users []protocol.User) {
	r.mu.Lock()
	replacements, err := protocol.UserReplacementIDs(r.authorizedUsers(), users)
	if err != nil {
		r.mu.Unlock()
		return
	}
	r.ipBlocks = protocol.RemapIPBlocks(r.ipBlocks, replacements)
	close := r.setUsers(users, replacements)
	publication := r.hourlyPublication()
	r.mu.Unlock()
	publication.apply()
	for _, lease := range close {
		lease.Close()
	}
}

// ApplyAuthorization publishes one committed snapshot under the admission lock.
// A delayed worker cannot restore users or blocks from an earlier transaction.
func (r *Registry) ApplyAuthorization(view state.AuthorizationView) bool {
	r.mu.Lock()
	if view.Sequence <= r.authorizationSequence || view.Revision < r.authorizationRevision {
		r.mu.Unlock()
		return false
	}
	var close []*Lease
	if r.authorizationSequence == 0 || view.Revision != r.authorizationRevision {
		replacements, err := protocol.UserReplacementIDs(r.authorizedUsers(), view.Users)
		if err != nil {
			r.mu.Unlock()
			return false
		}
		close = r.setUsers(view.Users, replacements)
	}
	r.ipBlocks = protocol.Clone(view.IPBlocks)
	if r.ipBlocks == nil {
		r.ipBlocks = map[string]protocol.IPBlock{}
	}
	r.authorizationSequence, r.authorizationRevision = view.Sequence, view.Revision
	publication := r.hourlyPublication()
	r.mu.Unlock()
	publication.apply()
	for _, lease := range close {
		lease.Close()
	}
	return true
}

// authorizedUsers excludes retained accounting-only generations.
func (r *Registry) authorizedUsers() []protocol.User {
	users := make([]protocol.User, 0, len(r.users))
	for _, user := range r.users {
		if len(user.policy.InboundTags) > 0 {
			users = append(users, user.policy)
		}
	}
	return users
}

// setUsers requires the admission lock and returns leases to close outside it.
func (r *Registry) setUsers(users []protocol.User, replacements map[int]int) []*Lease {
	r.rekeyUsers(replacements)
	r.reconcileAliases(users, replacements)
	next := map[int]*userState{}
	policies := map[int]protocol.User{}
	identities := map[int]identityIndex{}
	unchanged := map[int]bool{}
	for _, p := range users {
		policies[p.ID] = p
		identities[p.ID] = r.identities(p)
		old := r.users[p.ID]
		if old == nil {
			old = &userState{ips: map[string]int{}}
		}
		if old.speed == nil || !sameSpeed(old.policy, p) {
			old.speed = newSpeedPolicy(p)
		}
		next[p.ID] = old
	}
	var close []*Lease
	for _, l := range r.connections {
		p, ok := policies[l.Info.UserID]
		same, checked := unchanged[l.Info.UserID]
		if ok && !checked {
			same = sameIdentity(l.user.policy, p)
			unchanged[l.Info.UserID] = same
		}
		_, valid := identities[l.Info.UserID].lookup(l.identity, l.Info.InboundTag)
		if !ok || !same || !valid || !l.transit && !sourceAllowed(p, l.Info.SourceIP) {
			close = append(close, l)
		}
	}
	for _, p := range users {
		next[p.ID].policy = protocol.Clone(p)
		next[p.ID].identities = identities[p.ID]
	}
	// Retain removed counters until all associated leases finish and the sampler consumes them.
	for id, u := range r.users {
		if _, ok := next[id]; !ok {
			u.policy.InboundTags = nil
			u.identities = nil
			next[id] = u
		}
	}
	r.users = next
	return close
}
