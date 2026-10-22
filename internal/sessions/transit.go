package sessions

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func (r *Registry) transitIdentity(user protocol.User, binding protocol.TransitCredential) string {
	identity := protocol.TransitEmail(user.ID, binding)
	if epoch := r.epochs[binding.InboundTag]; epoch != "" {
		identity += "@" + epoch
	}
	return identity
}

func (r *Registry) isTransit(user protocol.User, identity, tag string) bool {
	for _, binding := range user.TransitCredentials {
		if binding.InboundTag == tag && r.transitIdentity(user, binding) == identity {
			return true
		}
	}
	if user.ReplacesID != 0 {
		user.ID, user.ReplacesID = user.ReplacesID, 0
		return r.isTransit(user, identity, tag)
	}
	return false
}

func (r *Registry) validIdentity(user protocol.User, identity, tag string) bool {
	if !eligible(user, tag) {
		return false
	}
	normal := protocol.UserEmail(user, tag)
	if epoch := r.epochs[tag]; epoch != "" {
		normal += "@" + epoch
	}
	if identity == normal || r.isTransit(user, identity, tag) {
		return true
	}
	if user.ReplacesID != 0 {
		user.ID, user.ReplacesID = user.ReplacesID, 0
		return r.validIdentity(user, identity, tag)
	}
	return false
}
