package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBootstrapNormalizesAcceptedAndStagedLegacyDNSWithoutStateRewrite(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"agent_id":"preserved-agent","revision":7,"config_revision":6,"sequence":42,"users":[],"config":{"xray":{"inbounds":[]},"users":[],"dns":{"mode":"smartdns","redirect":true,"upstreams":["203.0.113.53"]}},"desired_config":{"xray":{"inbounds":[],"dns":{"servers":["192.0.2.53"]}},"users":[],"dns":{"mode":"smartdns","redirect":true}}}`)
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	check := func(store *Store) {
		t.Helper()
		snapshot := store.Snapshot()
		if snapshot.AgentID != "preserved-agent" || snapshot.Revision != 7 || snapshot.ConfigRevision != 6 || snapshot.Sequence != 42 {
			t.Fatal("identity/revisions/accounting sequence changed", snapshot)
		}
		if snapshot.Config == nil || snapshot.DesiredConfig == nil || !bytes.Contains(snapshot.Config.Xray, []byte(`127.0.0.1`)) || !bytes.Contains(snapshot.DesiredConfig.Xray, []byte(`192.0.2.53`)) {
			t.Fatal("bootstrap lost effective accepted or staged DNS", snapshot.Config, snapshot.DesiredConfig)
		}
		for _, config := range []any{snapshot.Config, snapshot.DesiredConfig} {
			canonical, _ := json.Marshal(config)
			if bytes.Contains(canonical, []byte(`"mode"`)) || bytes.Contains(canonical, []byte(`"upstreams"`)) {
				t.Fatal("cached private compatibility escaped into current configuration", string(canonical))
			}
		}
	}
	check(store)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("DNS recovery required a durable state rewrite", err)
	}
	// A normal durable operation canonicalizes both cached snapshots without
	// adopting staged state or changing the authorization/accounting identity.
	if err := store.Ban(42, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(path)
	if err != nil || bytes.Contains(after, []byte(`"mode"`)) || bytes.Contains(after, []byte(`"upstreams"`)) {
		t.Fatal("next state write retained retired fields", err)
	}
	restarted, err := Open(dir)
	if err != nil {
		t.Fatal("offline restart failed after canonical persistence", err)
	}
	check(restarted)
}

func TestCachedDNSRetirementPreservesEffectiveNativeResolvers(t *testing.T) {
	for _, test := range []struct {
		name, mode, native, servers string
		redirect                    bool
	}{
		{"legacy missing", "smartdns", `{"inbounds":[]}`, `["127.0.0.1"]`, true},
		{"legacy null DNS", "smartdns", `{"inbounds":[],"dns":null}`, `["127.0.0.1"]`, true},
		{"legacy null servers", "smartdns", `{"inbounds":[],"dns":{"servers":null}}`, `["127.0.0.1"]`, true},
		{"legacy empty preserves options", "smartdns", `{"inbounds":[],"dns":{"servers":[],"queryStrategy":"UseIPv4"}}`, `["127.0.0.1"]`, true},
		{"explicit native wins", "smartdns", `{"inbounds":[],"dns":{"servers":[{"address":"192.0.2.53","port":5353}]}}`, `[{"address":"192.0.2.53","port":5353}]`, true},
		{"disabled redirect", "smartdns", `{"inbounds":[]}`, `null`, false},
		{"xray has no fallback", "xray", `{"inbounds":[]}`, `null`, true},
		{"current has no fallback", "", `{"inbounds":[]}`, `null`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"config":{"xray":%s,"users":[],"dns":{"mode":%q,"redirect":%t,"upstreams":["203.0.113.53"]}}}`, test.native, test.mode, test.redirect))
			var data Data
			if err := json.Unmarshal(raw, &data); err != nil {
				t.Fatal(err)
			}
			if err := normalizeCachedDNS(raw, &data); err != nil {
				t.Fatal(err)
			}
			var native struct {
				DNS struct {
					Servers       json.RawMessage
					QueryStrategy string
				}
			}
			if err := json.Unmarshal(data.Config.Xray, &native); err != nil {
				t.Fatal(err)
			}
			var actual, expected any
			_ = json.Unmarshal(native.DNS.Servers, &actual)
			_ = json.Unmarshal([]byte(test.servers), &expected)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("resolver changed", actual, expected)
			}
			if test.name == "legacy empty preserves options" && native.DNS.QueryStrategy != "UseIPv4" {
				t.Fatal("native options lost")
			}
			canonical, _ := json.Marshal(data)
			if err := normalizeCachedDNS(canonical, &data); err != nil {
				t.Fatal(err)
			}
			again, _ := json.Marshal(data)
			if !bytes.Equal(canonical, again) {
				t.Fatal("cached recovery is not idempotent")
			}
		})
	}
}

func TestCachedDNSRecoveryRejectsMalformedNativeFields(t *testing.T) {
	for _, native := range []string{
		`{"inbounds":[],"dns":[]}`, `{"inbounds":[],"dns":"invalid"}`,
		`{"inbounds":[],"dns":{"servers":{}}}`, `{"inbounds":[],"dns":{"servers":"127.0.0.1"}}`,
	} {
		raw := []byte(`{"config":{"xray":` + native + `,"dns":{"mode":"smartdns","redirect":true}}}`)
		var data Data
		_ = json.Unmarshal(raw, &data)
		if err := normalizeCachedDNS(raw, &data); err == nil {
			t.Fatal("malformed cached native DNS was replaced by loopback", native)
		}
	}
}
