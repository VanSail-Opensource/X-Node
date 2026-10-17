package xray

import (
	"encoding/json"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
)

func TestDomainBlocksPrecedeSuppliedAndSystemRules(t *testing.T) {
	c := protocol.Config{Xray: json.RawMessage(`{"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["full:blocked.example"],"outboundTag":"direct"}]}}`), Users: []protocol.User{}, BlockedDomains: []string{"full:blocked.example"}}
	prepared, err := Prepare(c)
	if err != nil {
		t.Fatal(err)
	}
	routing := prepared.Native["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	if rules[0].(map[string]any)["outboundTag"] != domainBlockTag {
		t.Fatal("domain policy was not first")
	}
	if prepared.Core == nil {
		t.Fatal("native core configuration was not built")
	}
}

func TestPreparedTransitHasIndependentNativeAuthentication(t *testing.T) {
	u := protocol.User{ID: 1, UUID: testUUID, InboundTags: []string{"in"}, TransitCredentials: []protocol.TransitCredential{{SourceNodeID: "source", InboundTag: "in", Generation: "v1", Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440012"}`)}}}
	c := protocol.Config{Xray: json.RawMessage(`{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":12345,"protocol":"vless","settings":{"decryption":"none"}}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}`), Users: []protocol.User{u}}
	prepared, err := Prepare(c)
	if err != nil {
		t.Fatal(err)
	}
	in := prepared.Native["inbounds"].([]any)[0].(map[string]any)
	accounts := in["settings"].(map[string]any)["clients"].([]any)
	if len(accounts) != 2 || accounts[0].(map[string]any)["id"] == accounts[1].(map[string]any)["id"] || accounts[0].(map[string]any)["email"] == accounts[1].(map[string]any)["email"] {
		t.Fatal("peer authentication was not isolated")
	}
}
