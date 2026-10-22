package protocol

import (
	"errors"
	"net/netip"
)

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
