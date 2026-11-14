package protocol

import (
	"errors"
	"net/netip"
)

// ValidateUsers checks an updated authorization view against the unchanged
// native configuration. An old failed utility setting must not veto unrelated
// user revocation or renewal after a cached-state restart.
func (config Config) ValidateUsers() error {
	if err := validateAuxiliaryUsers(config); err != nil {
		return err
	}
	return ValidateUsers(config.Users)
}

// Validate checks identities before a delta is merged into a map. Otherwise a
// later duplicate could hide an invalid upsert or silently undo a revocation.
func (delta UsersDelta) Validate() error {
	if len(delta.Upsert) > 100000 || len(delta.Remove) > 100000 {
		return errors.New("user delta exceeds bound")
	}
	seen := make(map[int]bool, len(delta.Upsert)+len(delta.Remove))
	for _, user := range delta.Upsert {
		if user.ID <= 0 || seen[user.ID] {
			return errors.New("invalid or duplicate user delta identity")
		}
		seen[user.ID] = true
	}
	for _, id := range delta.Remove {
		if id <= 0 || seen[id] {
			return errors.New("invalid, duplicate or conflicting user delta removal")
		}
		seen[id] = true
	}
	return nil
}

func validateRekeys(users []User) error {
	seen := map[int]bool{}
	for _, user := range users {
		if len(user.WhitelistedIPs) > 1000 {
			return errors.New("source whitelist exceeds bound")
		}
		ips := map[netip.Addr]bool{}
		for _, raw := range user.WhitelistedIPs {
			ip, err := netip.ParseAddr(raw)
			if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ips[ip] {
				return errors.New("invalid source whitelist address")
			}
			ips[ip] = true
		}
		if user.ReplacesID < 0 || user.ReplacesID == user.ID || user.ReplacesID > 0 && seen[user.ReplacesID] {
			return errors.New("invalid identity replacement")
		}
		if user.ReplacesID > 0 {
			seen[user.ReplacesID] = true
		}
	}
	return nil
}
