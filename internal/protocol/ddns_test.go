package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuiltinDDNSValidationKeepsLegacyNamedProviders(t *testing.T) {
	c := Config{Xray: json.RawMessage(`{"inbounds":[]}`), Users: []User{}, Providers: map[string]Provider{"builtin": {Type: "cloudflare"}}, DDNS: []DDNSJob{{ID: "internal", Provider: BuiltinDDNSProvider, IPv4: "auto", IPv4URL: "https://example.com/ip"}}}
	if err := c.Validate(); err != nil {
		t.Fatal("credential-free built-in discovery rejected", err)
	}
	c.DDNS[0] = DDNSJob{ID: "external", Provider: "builtin", Zone: "example.com", Name: "wan.example.com", IPv4: "auto", IPv4URL: "https://example.com/ip"}
	if err := c.Validate(); err != nil {
		t.Fatal("legacy provider named builtin changed meaning", err)
	}
	c.DDNS[0].Zone = ""
	if c.Validate() == nil {
		t.Fatal("external provider lost record validation")
	}
	c.DDNS[0] = DDNSJob{ID: "internal", Provider: BuiltinDDNSProvider, IPv4: "203.0.113.7"}
	if c.Validate() == nil {
		t.Fatal("built-in fixed address accepted instead of discovery")
	}
	event := DDNSChange{ID: "event", JobID: "wan", Generation: "generation", Sequence: 1, IPv4: "203.0.113.7", ObservedAt: time.Now()}
	if event.Validate() != nil {
		t.Fatal("valid event rejected")
	}
	event.IPv4 = "2001:db8::7"
	if event.Validate() == nil {
		t.Fatal("wrong address family accepted")
	}
}
