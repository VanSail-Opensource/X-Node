package protocol

import (
	"encoding/json"
	"testing"
)

func TestAuxiliaryInboundsCannotBypassManagedAccountIsolation(t *testing.T) {
	for _, body := range []string{
		`{"inbounds":[{"tag":"utility","protocol":"dokodemo-door","settings":{"clients":[]}}]}`,
		`{"inbounds":[{"tag":"_xnode_dns","protocol":"tunnel"}]}`,
		`{"inbounds":[{"tag":"utility","protocol":"tunnel"},{"tag":"utility","protocol":"dokodemo-door"}]}`,
	} {
		if _, err := AuxiliaryInboundTags(json.RawMessage(body)); err == nil {
			t.Fatalf("unsafe auxiliary document accepted: %s", body)
		}
	}
	config := Config{Xray: json.RawMessage(`{"inbounds":[{"tag":"utility","protocol":"tunnel"}]}`), Users: []User{{ID: 1, UUID: "secret", InboundTags: []string{"utility"}}}}
	if err := config.Validate(); err == nil {
		t.Fatal("managed user bound an unmetered auxiliary listener")
	}
}
