package sessions

import (
	"context"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestTelegramRekeyPreservesLeaseAndPeriodCounters(t *testing.T) {
	r := New()
	before := testUser()
	before.AccountingPeriod = "paid-term"
	r.SetUsers([]protocol.User{before})
	lease, err := acquire(r, before, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	after := before
	after.ID, after.ReplacesID = 99101, before.ID
	r.SetUsers([]protocol.User{after})
	if lease.Info.UserID != after.ID || lease.closed {
		t.Fatal("identity migration closed or misattributed a paid stream")
	}
	if len(r.AccountingCounters()) != 1 || r.AccountingCounters()[0].Period != "paid-term" {
		t.Fatal("lost accounting period")
	}
	stale, err := r.Acquire(context.Background(), before.ID, protocol.UserEmail(before, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
	if err != nil || stale.Info.UserID != after.ID {
		t.Fatalf("old authenticated mux lost owner: %v", err)
	}
	stale.Close()
	lease.Close()
	r.SetUsers([]protocol.User{after})
	if _, err = acquire(r, after, "192.0.2.1", "tcp"); err != nil {
		t.Fatal("repeat replacement was not idempotent", err)
	}
}

func TestTelegramRekeyDoesNotAcceptNumericIdentityCollision(t *testing.T) {
	r := New()
	before := testUser()
	after := before
	after.ID, after.ReplacesID = 99101, before.ID
	after.UUID = "550e8400-e29b-41d4-a716-446655440099"
	r.SetUsers([]protocol.User{after})
	if _, err := acquire(r, before, "192.0.2.1", "tcp"); err == nil {
		t.Fatal("old number bypassed credential generation")
	}
}
