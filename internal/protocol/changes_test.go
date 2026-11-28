package protocol

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestAllActionsAndConfigurationFieldsHaveConsumers(t *testing.T) {
	for _, name := range CommandNames {
		if ClassifyAction(name) == ReconcileAction {
			t.Errorf("unclassified command %s", name)
		}
	}
	fields := map[string]bool{"BlockedDomains": true, "Xray": true, "Users": true, "Providers": true, "Certificates": true, "InboundCertificates": true, "DDNS": true, "DNS": true, "Firewall": true, "BlockedPorts": true, "AssetHashes": true, "Updates": true, "Telemetry": true, "Torrent": true, "MemberOutbounds": true}
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		if !fields[typ.Field(i).Name] {
			t.Errorf("document consumer for %s", typ.Field(i).Name)
		}
	}
	if ClassifyAction("future.command") != ReconcileAction {
		t.Fatal("unknown action bypassed conservative reconciliation")
	}
}

func TestNativeProjectionRetainsCanonicalAccountComparison(t *testing.T) {
	old := Config{
		Xray: json.RawMessage(`{"routing":{},"geodata":{"outbound":"direct","cron":"0 1 * * *"}}`),
		Users: []User{{
			ID: 1, UUID: "owner", InboundTags: []string{"paid"},
			Credentials: map[string]json.RawMessage{"paid": json.RawMessage(`{"level":9007199254740993,"mode":"sample"}`)},
		}},
	}
	next := Clone(old)
	next.Xray = json.RawMessage(`{"geodata":{"cron":"0 2 * * *","outbound":"direct"}, "routing":{}}`)
	next.Torrent.BanSeconds = 60
	next.Users[0].Credentials["paid"] = json.RawMessage(`{ "mode": "sample", "level": 9007199254740993 }`)
	next.Users[0].WhitelistEnabled = true
	next.Users[0].WhitelistedIPs = []string{"192.0.2.1"}
	next.Users[0].BlockNew = true
	until := time.Now().UTC().Add(time.Hour)
	next.Users[0].ValidUntil = &until
	snapshot := Clone(next)
	if got := Classify(old, next); got.Native || got.Assets || !got.Registry {
		t.Fatalf("unrelated changes affected native/asset classification: %+v", got)
	}
	oldIdentity, nextIdentity := NativeIdentity(old), NativeIdentity(next)
	if !bytes.Equal(oldIdentity, nextIdentity) || !bytes.Contains(nextIdentity, []byte("9007199254740993")) {
		t.Fatal("canonical native cache key changed or lost credential precision")
	}
	if !sameJSON(next, snapshot) {
		t.Fatal("classification mutated the source")
	}

	next.Users[0].Credentials["paid"] = json.RawMessage(`{"mode":"sample","level":9007199254740992}`)
	if !Classify(old, next).Native || bytes.Equal(oldIdentity, NativeIdentity(next)) {
		t.Fatal("distinct account values were classified as equal")
	}
}

func TestNativeProjectionPreservesAccountOrderAndEmptyShape(t *testing.T) {
	old := Config{Xray: json.RawMessage(`{}`), Users: []User{
		{ID: 1, InboundTags: []string{"paid"}}, {ID: 2, InboundTags: []string{"paid"}},
	}}
	next := Clone(old)
	next.Users[0], next.Users[1] = next.Users[1], next.Users[0]
	if !Classify(old, next).Native {
		t.Fatal("native account order changed without reconciliation")
	}
	old.Users, next.Users = nil, []User{}
	if Classify(old, next).Native || !bytes.Equal(NativeIdentity(old), NativeIdentity(next)) {
		t.Fatal("empty native account lists changed classification")
	}
}

func TestRegistryUtilityAndFirewallChangesDoNotCompileNative(t *testing.T) {
	base := Config{Xray: json.RawMessage(`{"inbounds":[]}`), Users: []User{{ID: 1, UUID: "owner", InboundTags: []string{"paid"}}}}
	cases := map[string]func(*Config){
		"control":          func(c *Config) { c.Users[0].BlockNew = true },
		"speed":            func(c *Config) { c.Users[0].SpeedLimitMbps = 10 },
		"ports":            func(c *Config) { c.BlockedPorts = []PortRange{{From: 80, To: 80}} },
		"firewall":         func(c *Config) { c.Firewall.Enabled = true },
		"telemetry":        func(c *Config) { c.Telemetry.SampleSeconds = 5 },
		"update":           func(c *Config) { c.Updates.Enabled = true },
		"ddns":             func(c *Config) { c.DDNS = []DDNSJob{{ID: "changed"}} },
		"provider":         func(c *Config) { c.Providers = map[string]Provider{"unused": {Type: "cloudflare"}} },
		"torrent-duration": func(c *Config) { c.Torrent.BanSeconds = 50 },
		"asset-schedule":   func(c *Config) { c.Xray = json.RawMessage(`{"inbounds":[],"geodata":{"interval_hours":24}}`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			next := Clone(base)
			mutate(&next)
			if Classify(base, next).Native {
				t.Fatal("unrelated native compilation")
			}
		})
	}
	next := Clone(base)
	next.Users[0].UUID = "replacement"
	if !Classify(base, next).Native {
		t.Fatal("credential change skipped native account update")
	}
	next = Clone(base)
	next.Xray = json.RawMessage(`{"inbounds":[],"geodata":{"assets":[{"file":"geosite.dat","url":"https://example.com/site"}]}}`)
	if !Classify(base, next).Native {
		t.Fatal("asset input change skipped preparation")
	}
}
