package sessions

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

type identityKey struct{ tag, value string }

// A false value is a member identity; true marks an authenticated transit hop.
type identityIndex map[identityKey]bool

func (index identityIndex) lookup(identity, tag string) (transit, valid bool) {
	transit, valid = index[identityKey{tag: tag, value: identity}]
	return transit, valid
}

// identities builds the credential and epoch-bound labels only on policy changes.
func (r *Registry) identities(user protocol.User) identityIndex {
	index := identityIndex{}
	for _, id := range []int{user.ID, user.ReplacesID} {
		if id == 0 {
			continue
		}
		candidate := user
		candidate.ID, candidate.ReplacesID = id, 0
		for _, tag := range candidate.InboundTags {
			label := protocol.UserEmail(candidate, tag)
			if epoch := r.epochs[tag]; epoch != "" {
				label += "@" + epoch
			}
			index[identityKey{tag: tag, value: label}] = false
		}
		for _, binding := range candidate.TransitCredentials {
			if !eligible(candidate, binding.InboundTag) {
				continue
			}
			label := protocol.TransitEmail(id, binding)
			if epoch := r.epochs[binding.InboundTag]; epoch != "" {
				label += "@" + epoch
			}
			index[identityKey{tag: binding.InboundTag, value: label}] = true
		}
	}
	return index
}
