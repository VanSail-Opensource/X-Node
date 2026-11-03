package protocol

import (
	"errors"
	"net/netip"
	"time"
)

const AutomaticLeaseCapability = "volatile_firewall_leases_v1"
const AutomaticLeaseCommand = "firewall.leases.update"
const MaxAutomaticLeaseBatch = 256
const MaxAutomaticLeases = 100000

type AutomaticLeaseGrant struct {
	IP         string    `json:"ip"`
	Generation uint64    `json:"generation,string"`
	Until      time.Time `json:"until"`
}
type AutomaticLeaseUpdate struct {
	Epoch  string                `json:"epoch"`
	Leases []AutomaticLeaseGrant `json:"leases"`
}
type AutomaticLeaseAck struct {
	Epoch      string `json:"epoch"`
	Generation uint64 `json:"generation,string"`
}

func (u AutomaticLeaseUpdate) Validate(now time.Time) error {
	if !ValidName(u.Epoch) || len(u.Epoch) > 64 || len(u.Leases) == 0 || len(u.Leases) > MaxAutomaticLeaseBatch {
		return errors.New("invalid automatic lease batch")
	}
	seen := map[netip.Addr]bool{}
	for _, grant := range u.Leases {
		ip, err := AutomaticLeaseAddress(grant.IP)
		if err != nil || ip.Zone() != "" || ip.Unmap().String() != grant.IP || seen[ip] || grant.Generation == 0 || grant.Until.IsZero() || grant.Until.After(now.Add(2*8760*time.Hour+time.Minute)) {
			return errors.New("invalid automatic lease grant")
		}
		if err := (FirewallExemption{IP: grant.IP, Generation: "automatic", Until: grant.Until}).Validate(); err != nil {
			return errors.New("invalid automatic lease address")
		}
		seen[ip] = true
	}
	return nil
}

var automaticGlobalIPv6 = netip.MustParsePrefix("2000::/3")
var automaticNonPublicPrefixes = func() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		prefixes = append(prefixes, netip.MustParsePrefix(raw))
	}
	return prefixes
}()

func AutomaticLeaseAddress(raw string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, errors.New("invalid automatic lease address")
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Is6() && !automaticGlobalIPv6.Contains(ip) {
		return netip.Addr{}, errors.New("non-public automatic lease address")
	}
	for _, prefix := range automaticNonPublicPrefixes {
		if prefix.Contains(ip) {
			return netip.Addr{}, errors.New("non-public automatic lease address")
		}
	}
	return ip, nil
}

func AutomaticLeaseSchema() map[string]any {
	schema := Schema(AutomaticLeaseUpdate{})
	fields := schema["properties"].(map[string]any)
	fields["epoch"].(map[string]any)["minLength"] = 1
	fields["epoch"].(map[string]any)["maxLength"] = 64
	leases := fields["leases"].(map[string]any)
	leases["minItems"], leases["maxItems"] = 1, MaxAutomaticLeaseBatch
	grant := leases["items"].(map[string]any)["properties"].(map[string]any)
	grant["generation"].(map[string]any)["pattern"] = "^[1-9][0-9]*$"
	grant["ip"] = map[string]any{"anyOf": []any{map[string]any{"type": "string", "format": "ipv4"}, map[string]any{"type": "string", "format": "ipv6"}}}
	return schema
}
