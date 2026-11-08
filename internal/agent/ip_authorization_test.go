package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestIPControlRemainsScopedAcrossReplacementAndRestart(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := protocol.User{ID: 1, UUID: "550e8400-e29b-41d4-a716-446655440000", InboundTags: []string{"in"}, AccountingPeriod: "paid"}
	view, err := store.AuthorizeView([]protocol.User{before}, 1)
	if err != nil {
		t.Fatal(err)
	}
	registry := sessions.New()
	registry.ApplyAuthorization(view)
	a := &Agent{Store: store, Registry: registry}
	command := func(control protocol.IPControl) error {
		t.Helper()
		args, err := json.Marshal(control)
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.connectionCommand("ips.control", args)
		return err
	}
	if err := command(protocol.IPControl{UserID: before.ID, SourceIP: "192.0.2.1", BlockSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	after := before
	after.ID, after.ReplacesID = 2, 1
	view, err = store.AuthorizeView([]protocol.User{after}, 2)
	if err != nil {
		t.Fatal(err)
	}
	registry.ApplyAuthorization(view)
	key := sessions.IPBlockKey(after.ID, "192.0.2.1")
	deadline := store.Snapshot().IPBlocks[key].Until
	if deadline.IsZero() {
		t.Fatal("replacement lost persisted block")
	}
	if err := command(protocol.IPControl{UserID: before.ID, SourceIP: "192.0.2.1", Unblock: true, Drop: true}); err == nil {
		t.Fatal("stale numeric subject was accepted")
	}
	if !store.Snapshot().IPBlocks[key].Until.Equal(deadline) {
		t.Fatal("stale unblock changed replacement block")
	}
	assertBlocked := func(registry *sessions.Registry) {
		t.Helper()
		for _, user := range []protocol.User{before, after} {
			for _, network := range []string{"tcp", "udp"} {
				lease, err := registry.Acquire(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", network, 443, nil)
				if err == nil {
					lease.Close()
					t.Fatalf("blocked credential admitted: user=%d network=%s", user.ID, network)
				}
			}
		}
	}
	assertBlocked(registry)
	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	restored := sessions.New()
	restored.ApplyAuthorization(reopened.CurrentAuthorization())
	assertBlocked(restored)
	a.Store, a.Registry = reopened, restored
	if err := command(protocol.IPControl{UserID: after.ID, SourceIP: "192.0.2.1", Unblock: true}); err != nil {
		t.Fatal(err)
	}
	lease, err := restored.Acquire(context.Background(), after.ID, protocol.UserEmail(after, "in"), "in", "192.0.2.1", "example.com:443", "udp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
}
