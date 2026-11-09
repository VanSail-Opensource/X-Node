package protocol

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestDNSRetirementPreservesEffectiveNativeResolvers(t *testing.T) {
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
	} {
		t.Run(test.name, func(t *testing.T) {
			input := Config{Xray: json.RawMessage(test.native), Users: []User{}, DNS: DNSPolicy{Mode: test.mode, Redirect: test.redirect, Upstreams: []string{"203.0.113.53"}}}
			original := append([]byte(nil), input.Xray...)
			got, err := input.NormalizeDNS()
			if err != nil {
				t.Fatal(err)
			}
			if got.DNS.Mode != "xray" || !bytes.Equal(input.Xray, original) || !reflect.DeepEqual(got.DNS.Upstreams, input.DNS.Upstreams) {
				t.Fatal("migration changed caller or inactive upstream field", got)
			}
			var native struct {
				DNS struct {
					Servers       json.RawMessage `json:"servers"`
					QueryStrategy string          `json:"queryStrategy"`
				} `json:"dns"`
			}
			if err = json.Unmarshal(got.Xray, &native); err != nil {
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
			again, err := got.NormalizeDNS()
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatal("migration is not idempotent", err)
			}
		})
	}
}

func TestLegacyDNSMigrationRejectsMalformedNativeFields(t *testing.T) {
	for _, native := range []string{
		`{"inbounds":[],"dns":[]}`, `{"inbounds":[],"dns":"invalid"}`,
		`{"inbounds":[],"dns":{"servers":{}}}`, `{"inbounds":[],"dns":{"servers":"127.0.0.1"}}`,
	} {
		config := Config{Xray: json.RawMessage(native), Users: []User{}, DNS: DNSPolicy{Mode: "smartdns", Redirect: true}}
		if _, err := config.NormalizeDNS(); err == nil {
			t.Fatal("malformed native DNS was replaced by loopback", native)
		}
	}
}

func TestPublicDNSParseMigratesLegacyAndRejectsMissingXrayServers(t *testing.T) {
	raw := []byte(`{"xray":{"inbounds":[]},"users":[],"dns":{"mode":"smartdns","redirect":true,"upstreams":["203.0.113.53"]}}`)
	got, err := ParseConfig(raw)
	if err != nil || got.DNS.Mode != "xray" || !bytes.Contains(got.Xray, []byte(`127.0.0.1`)) {
		t.Fatal("legacy parse did not preserve resolver", got, err)
	}
	for _, mode := range []string{"xray", "unknown"} {
		input := Config{Xray: json.RawMessage(`{"inbounds":[]}`), Users: []User{}, DNS: DNSPolicy{Mode: mode, Redirect: true}}
		if input.Validate() == nil {
			t.Fatal("missing/unsupported Xray DNS accepted", mode)
		}
	}
}
