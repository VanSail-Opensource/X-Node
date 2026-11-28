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
	a, b := nativeSettings(old), nativeSettings(next)
	changes := Changes{
		Native:       !sameNativeSettings(a, b) || !sameNativeUsers(old.Users, next.Users),
		Certificates: !sameJSON(certificateInputs(old), certificateInputs(next)),
		Assets:       !sameJSON(old.AssetHashes, next.AssetHashes) || (!bytes.Equal(old.Xray, next.Xray) && !sameJSON(assetPolicy(old.Xray), assetPolicy(next.Xray))),
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
	fields := nativeFields(nativeSettings(c))
	users, ok := canonicalNativeUsers(c.Users)
	if fields == nil || !ok {
		return nil
	}
	fields["users"] = users
	identity, _ := json.Marshal(fields)
	return identity
}

func nativeSettings(c Config) Config {
	// Start with the full value so future fields conservatively affect native
	// classification. Never change the source or its shared nested fields.
	c.Users = nil // Compared separately without normalizing every account to JSON.
	c.Providers = nil
	c.DDNS = nil
	c.Updates = UpdatePolicy{}
	c.Telemetry = TelemetryPolicy{}
	c.Firewall = FirewallPolicy{}
	c.BlockedPorts = nil
	// Ban duration changes update the dispatch bridge, not Xray configuration.
	c.Torrent.BanSeconds = 0
	return c
}

func sameNativeSettings(a, b Config) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	left, right := nativeFields(a), nativeFields(b)
	return left != nil && right != nil && sameJSON(left, right)
}

func nativeFields(c Config) map[string]any {
	b, _ := json.Marshal(c)
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil
	}
	for _, key := range []string{"users", "providers", "ddns", "updates", "telemetry", "firewall", "blocked_ports"} {
		delete(fields, key)
	}
	if native, ok := fields["xray"].(map[string]any); ok {
		delete(native, "geodata")
	}
	return fields
}

func nativeUser(u User) User {
	u.WhitelistEnabled = false
	u.WhitelistedIPs = nil
	u.ReplacesID = 0
	u.ActiveIPLimit = 0
	u.ConnectionLimit = 0
	u.SpeedLimitMbps = 0
	u.BurstSpeedLimitMbps = 0
	u.SpeedLimitAfterSeconds = 0
	u.SpeedLimitResetSeconds = 0
	u.BlockNew = false
	u.AccountingPeriod = ""
	u.ValidUntil = nil
	return u
}

func sameNativeUsers(a, b []User) bool {
	if len(a) != len(b) {
		return false
	}
	for i, user := range a {
		left, right := nativeUser(user), nativeUser(b[i])
		if reflect.DeepEqual(left, right) {
			continue
		}
		// Raw account JSON may differ in formatting or map-key order only.
		// Preserve the canonical comparison for just the differing accounts.
		x, ok := canonicalNativeUsers([]User{left})
		y, valid := canonicalNativeUsers([]User{right})
		if !ok || !valid || !sameJSON(x, y) {
			return false
		}
	}
	return true
}

func canonicalNativeUsers(users []User) ([]any, bool) {
	projected := make([]User, len(users))
	for i, u := range users {
		projected[i] = nativeUser(u)
	}
	raw, err := json.Marshal(projected)
	if err != nil {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// IDs and protocol-specific credential values must remain lossless.
	decoder.UseNumber()
	var canonical []any
	if err := decoder.Decode(&canonical); err != nil {
		return nil, false
	}
	return canonical, true
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

func assetPolicy(raw json.RawMessage) map[string]any {
	var root map[string]any
	_ = json.Unmarshal(raw, &root)
	policy, _ := root["geodata"].(map[string]any)
	delete(policy, "interval_hours")
	delete(policy, "cron")
	if len(policy) == 0 {
		policy = nil
	}
	return policy
}

func sameJSON(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
