package sessions

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestWhitelistOnlyChecksMemberIngressAndKeepsTransit(t *testing.T) {
	r, user := New(), testUser()
	user.WhitelistEnabled = true
	user.WhitelistedIPs = []string{"192.0.2.1"}
	binding := protocol.TransitCredential{SourceNodeID: "first-node", InboundTag: "in", Generation: "route-1", Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440011"}`)}
	user.TransitCredentials = []protocol.TransitCredential{binding}
	r.SetUsers([]protocol.User{user})
	first, err := acquire(r, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquire(r, user, "192.0.2.10", "tcp"); err == nil {
		t.Fatal("node source address let ordinary member credentials bypass whitelist")
	}
	transit, err := r.AcquireTracked(context.Background(), user.ID, protocol.TransitEmail(user.ID, binding), "in", "192.0.2.10", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal("forwarded hop incorrectly checked member IP list", err)
	}
	defer transit.Finish()
	user.WhitelistedIPs = nil
	r.SetUsers([]protocol.User{user})
	if !first.closed || transit.closed {
		t.Fatal("whitelist removal must close ingress only")
	}
	transit.Account(true, 123)
	if r.Counters()[user.ID][0] != 123 {
		t.Fatal("transit bypass lost accounting")
	}
	user.TransitCredentials = nil
	r.SetUsers([]protocol.User{user})
	if !transit.closed {
		t.Fatal("removed routing authorization retained transit session")
	}
}

func TestRekeyedTransitRetainsFirstHopWhitelistException(t *testing.T) {
	r, user := New(), testUser()
	binding := protocol.TransitCredential{SourceNodeID: "first-node", InboundTag: "in", Generation: "route-1", Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440011"}`)}
	user.TransitCredentials = []protocol.TransitCredential{binding}
	oldID, identity := user.ID, protocol.TransitEmail(user.ID, binding)
	r.SetUsers([]protocol.User{user})
	user.ID, user.ReplacesID = 123456, oldID
	user.WhitelistEnabled = true
	r.SetUsers([]protocol.User{user})
	lease, err := r.AcquireTracked(context.Background(), oldID, identity, "in", "192.0.2.10", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal("authenticated delayed transit rejected after identity migration", err)
	}
	defer lease.Finish()
	if lease.Info.UserID != user.ID || !lease.transit {
		t.Fatal("delayed transit misattributed or treated as member ingress")
	}
}
