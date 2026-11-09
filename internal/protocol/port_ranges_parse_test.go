package protocol

import (
	"encoding/json"
	"testing"
)

func TestPublicConfigParseKeepsFirewallIntervalsCompact(t *testing.T) {
	input := Config{Xray: json.RawMessage(`{"inbounds":[]}`), Users: []User{}, Firewall: FirewallPolicy{TCPPorts: []int{443, 443}, TCPPortRanges: []PortRange{{From: 1000, To: 65535}, {From: 444, To: 999}}}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Firewall.TCPPortRanges) != 1 || got.Firewall.TCPPortRanges[0] != (PortRange{From: 444, To: 65535}) || len(got.Firewall.TCPPorts) != 1 {
		t.Fatal("public parse did not canonicalize compact ranges", got.Firewall)
	}
}

func TestLegacySingletonForwardOrderingRemainsReadable(t *testing.T) {
	p := FirewallPolicy{Forward: []Forward{{Port: 443, TargetIP: "192.0.2.1", TargetPort: 443, Network: "tcp"}, {Port: 443, TargetIP: "192.0.2.2", TargetPort: 8443, Network: "tcp"}}}
	got, err := p.NormalizePortRanges()
	if err != nil || len(got.Forward) != 2 || got.Forward[0] != p.Forward[0] || got.Forward[1] != p.Forward[1] {
		t.Fatal("accepted singleton forwarding order changed", got, err)
	}
}
