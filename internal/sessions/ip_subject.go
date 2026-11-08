package sessions

import (
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// DropIPSubject captures only leases of the expected current credential/period.
// It does not follow numeric replacement aliases. Closing captured leases outside
// the admission lock cannot accidentally close a newly admitted connection.
func (r *Registry) DropIPSubject(ip string, expected *protocol.User) (int, error) {
	r.mu.RLock()
	if expected != nil {
		current := r.users[expected.ID]
		if expected.ID <= 0 || current == nil || len(current.policy.InboundTags) == 0 || !sameIdentity(current.policy, *expected) {
			r.mu.RUnlock()
			return 0, errors.New("IP control subject changed")
		}
	}
	var close []*Lease
	for _, lease := range r.connections {
		if lease.Info.SourceIP == ip && (expected == nil || lease.Info.UserID == expected.ID) {
			close = append(close, lease)
		}
	}
	r.mu.RUnlock()
	for _, lease := range close {
		lease.Close()
	}
	return len(close), nil
}
