package protocol

import (
	"encoding/json"
	"testing"
)

func TestAgentRejectsUnresolvedIPGeodata(t *testing.T) {
	for _, document := range []string{
		`{"inbounds":[],"routing":{"rules":[{"ip":["geoip:cn"]}]}}`,
		`{"inbounds":[],"dns":{"servers":[{"address":"1.1.1.1","expectedIPs":["geoip:cn"]}]}}`,
		`{"inbounds":[],"routing":{"rules":[{"sourceIP":["ext:renamed.dat:cn"]}]}}`,
		`{"inbounds":[],"geodata":{"assets":[{"file":"geoip.dat"}]}}`,
	} {
		if err := ValidateNativePolicies(Config{Xray: json.RawMessage(document)}); err == nil {
			t.Fatalf("accepted IP geodata: %s", document)
		}
	}
	if err := ValidateNativePolicies(Config{Xray: json.RawMessage(`{"inbounds":[],"routing":{"rules":[{"domain":["geosite:google"]}]}}`)}); err != nil {
		t.Fatal(err)
	}
}

func TestSourceFilterRejectsRealityOverlap(t *testing.T) {
	c := Config{Xray: json.RawMessage(`{"inbounds":[{"tag":"plain","port":443,"protocol":"vless"},{"tag":"reality","port":443,"protocol":"vless","streamSettings":{"security":"reality"}}]}`), Firewall: FirewallPolicy{Enabled: true, SourceGeoIP: &SourceGeoIPPolicy{Generation: "v1", Prefixes: []string{"1.0.1.0/24"}, Listeners: []SourceGeoIPListener{{Port: 443, Network: "tcp"}}}}}
	if err := ValidateNativePolicies(c); err == nil {
		t.Fatal("REALITY overlap accepted")
	}
	c.Xray = json.RawMessage(`{"inbounds":[{"tag":"plain","port":443,"protocol":"vless"}]}`)
	if err := ValidateNativePolicies(c); err != nil {
		t.Fatal(err)
	}
}
