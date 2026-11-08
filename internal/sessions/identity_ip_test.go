package sessions

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func identityIPUser(id int, uuid string) protocol.User {
	user := testUser()
	user.ID, user.UUID, user.AccountingPeriod = id, uuid, "purchase-one"
	user.ActiveIPLimit, user.ConnectionLimit = 0, 0
	return user
}

func assertIPDenied(t *testing.T, registry *Registry, id int, identity, ip, network string) {
	t.Helper()
	lease, err := registry.Acquire(context.Background(), id, identity, "in", ip, "example.com:443", network, 443, nil)
	if err == nil {
		lease.Close()
		t.Fatal("blocked source was admitted")
	}
	if err.Error() != "ip_temp_block" {
		t.Fatalf("source failed for another reason: %v", err)
	}
}

func TestVerifiedIdentityReplacementPreservesScopedIPRestrictions(t *testing.T) {
	registry := New()
	before := identityIPUser(1, testUser().UUID)
	other := identityIPUser(2, "550e8400-e29b-41d4-a716-446655440002")
	registry.SetUsers([]protocol.User{before, other})
	after := before
	after.ID, after.ReplacesID = 100, before.ID
	now := time.Now().UTC()
	blocks := map[string]protocol.IPBlock{}
	add := func(user int, ip string, hours int) {
		blocks[IPBlockKey(user, ip)] = protocol.IPBlock{UserID: user, SourceIP: ip, Until: now.Add(time.Duration(hours) * time.Hour)}
	}
	add(before.ID, "192.0.2.1", 2)
	add(after.ID, "192.0.2.1", 1)
	add(before.ID, "192.0.2.3", 1)
	add(after.ID, "192.0.2.3", 4)
	add(0, "192.0.2.2", 3)
	add(other.ID, "192.0.2.1", 3)
	registry.RestoreIPBlocks(blocks)
	registry.SetUsers([]protocol.User{after, other})
	registry.SetUsers([]protocol.User{after, other}) // Exact replay must not shorten or move restrictions twice.
	registry.mu.RLock()
	got := protocol.Clone(registry.ipBlocks)
	registry.mu.RUnlock()
	if len(got) != 4 || got[IPBlockKey(after.ID, "192.0.2.1")].Until != now.Add(2*time.Hour) || got[IPBlockKey(after.ID, "192.0.2.3")].Until != now.Add(4*time.Hour) {
		t.Fatal("replacement lost restrictions or chose a shorter collision expiry")
	}
	if got[IPBlockKey(0, "192.0.2.2")] != blocks[IPBlockKey(0, "192.0.2.2")] || got[IPBlockKey(other.ID, "192.0.2.1")] != blocks[IPBlockKey(other.ID, "192.0.2.1")] {
		t.Fatal("replacement changed a global or unrelated user's restriction")
	}
	for _, network := range []string{"tcp", "udp"} {
		assertIPDenied(t, registry, after.ID, protocol.UserEmail(after, "in"), "192.0.2.1", network)
		assertIPDenied(t, registry, before.ID, protocol.UserEmail(before, "in"), "192.0.2.1", network)
		assertIPDenied(t, registry, other.ID, protocol.UserEmail(other, "in"), "192.0.2.1", network)
		assertIPDenied(t, registry, other.ID, protocol.UserEmail(other, "in"), "192.0.2.2", network)
	}
	lease, err := registry.Acquire(context.Background(), before.ID, protocol.UserEmail(before, "in"), "in", "198.51.100.1", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal("verified old mux alias lost authorization", err)
	}
	if lease.Info.UserID != after.ID {
		t.Fatal("old mux alias was attributed to another owner")
	}
	lease.Close()
}

func TestIdentityReplacementRetainsOriginalAccountingKeysAndLateBytes(t *testing.T) {
	registry := New()
	before := identityIPUser(1, testUser().UUID)
	registry.SetUsers([]protocol.User{before})
	lease, err := registry.AcquireTracked(context.Background(), before.ID, protocol.UserEmail(before, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease.Account(true, 10)
	after := before
	after.ID, after.ReplacesID = 100, before.ID
	registry.SetUsers([]protocol.User{after})
	if lease.closed || lease.Info.UserID != after.ID {
		t.Fatal("verified replacement revoked a paid stream")
	}
	lease.Close()
	lease.Account(false, 12) // Native copying may finish after logical closure.
	lease.Finish()
	fresh, err := registry.AcquireTracked(context.Background(), after.ID, protocol.UserEmail(after, "in"), "in", "192.0.2.2", "example.com:443", "udp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Account(true, 3)
	fresh.Close()
	fresh.Finish()
	counters := registry.AccountingCounters()
	if len(counters) != 2 {
		t.Fatalf("lost original/new period counters: %+v", counters)
	}
	for _, counter := range counters {
		if counter.Period != before.AccountingPeriod {
			t.Fatal("replacement changed the purchased accounting period")
		}
		switch counter.UserID {
		case before.ID:
			if counter.Upload != 10 || counter.Download != 12 {
				t.Fatal("late original-period bytes were moved or lost")
			}
		case after.ID:
			if counter.Upload != 3 || counter.Download != 0 {
				t.Fatal("old usage was replayed as fresh replacement usage")
			}
		default:
			t.Fatal("unexpected accounting owner")
		}
	}
}
