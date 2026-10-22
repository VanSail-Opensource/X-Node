package protocol

import (
	"bytes"
	"encoding/json"
	"reflect"
)

// Changes identifies independent consumers of an authoritative configuration.
// Unclassified future fields conservatively require native preparation.
type Changes struct {
	Native, Certificates, Assets, Firewall, Utilities, Registry bool
}

// Classify never replaces Config.Validate or authorization. Runtime properties
// of users are kept separate from their native authentication accounts.
func Classify(old, next Config) Changes {
	a, b := nativeIdentity(old), nativeIdentity(next)
	changes := Changes{
		Native:       !sameJSON(a, b),
		Certificates: !sameJSON(certificateInputs(old), certificateInputs(next)),
		Assets:       !sameJSON(assetInputs(old), assetInputs(next)),
		Firewall:     !sameJSON(old.Firewall, next.Firewall),
		Utilities:    !sameJSON([]any{old.Providers, old.DDNS, old.Updates, old.Telemetry}, []any{next.Providers, next.DDNS, next.Updates, next.Telemetry}),
		Registry:     !sameJSON([]any{old.Users, old.BlockedPorts}, []any{next.Users, next.BlockedPorts}),
	}
	changes.Native = changes.Native || changes.Certificates || changes.Assets
	return changes
}

// NativeIdentity excludes only fields with explicitly classified non-core
// consumers. It is also suitable for memory-only validation cache keys.
func NativeIdentity(c Config) []byte {
	b, _ := json.Marshal(nativeIdentity(c))
	return b
}

func nativeIdentity(c Config) map[string]any {
	// Start with every field so a newly added field cannot silently bypass work.
	b, _ := json.Marshal(c)
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	for _, key := range []string{"users", "providers", "ddns", "updates", "telemetry", "firewall", "blocked_ports"} {
		delete(fields, key)
	}
	users := make([]any, 0, len(c.Users))
	for _, u := range c.Users {
		raw, _ := json.Marshal(u)
		var identity map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		_ = decoder.Decode(&identity)
		for _, key := range []string{"whitelist_enabled", "whitelisted_ips", "replaces_id", "active_ip_limit", "connection_limit", "speed_limit_mbps", "burst_speed_limit_mbps", "speed_limit_after_seconds", "speed_limit_reset_seconds", "block_new", "accounting_period", "valid_until"} {
			delete(identity, key)
		}
		users = append(users, identity)
	}
	fields["users"] = users
	if native, ok := fields["xray"].(map[string]any); ok {
		delete(native, "geodata")
	}
	// Ban duration changes update the dispatch bridge, not Xray configuration.
	if torrent, ok := fields["torrent"].(map[string]any); ok {
		delete(torrent, "ban_seconds")
	}
	return fields
}

func certificateInputs(c Config) any {
	providers := map[string]Provider{}
	for _, cert := range c.Certificates {
		if cert.Provider != "" {
			providers[cert.Provider] = c.Providers[cert.Provider]
		}
	}
	return []any{c.Certificates, c.InboundCertificates, providers}
}

func assetInputs(c Config) any {
	var root map[string]any
	_ = json.Unmarshal(c.Xray, &root)
	policy, _ := root["geodata"].(map[string]any)
	delete(policy, "interval_hours")
	delete(policy, "cron")
	if len(policy) == 0 {
		policy = nil
	}
	return []any{c.AssetHashes, policy}
}

func sameJSON(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
