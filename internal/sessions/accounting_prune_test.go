package sessions

import (
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAccountingPruneRetainsBytesArrivingAfterSnapshot(t *testing.T) {
	registry, user := New(), testUser()
	user.AccountingPeriod = "paid"
	registry.SetUsers([]protocol.User{user})
	lease, err := acquire(registry, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	lease.Account(true, 10)
	captured := registry.AccountingCounters()
	lease.Account(false, 7)
	lease.Close()
	registry.SetUsers(nil)
	registry.PruneAccounting(captured)
	remaining := registry.AccountingCounters()
	if len(remaining) != 1 || remaining[0].Upload != 10 || remaining[0].Download != 7 {
		t.Fatalf("uncaptured final bytes were pruned: %+v", remaining)
	}
	registry.PruneAccounting(remaining)
	if len(registry.AccountingCounters()) != 0 {
		t.Fatal("persisted inactive counter was retained")
	}
}

func TestAccountingPruneDoesNotRetireReplacementGeneration(t *testing.T) {
	registry, user := New(), testUser()
	user.AccountingPeriod = "paid"
	registry.SetUsers([]protocol.User{user})
	old, err := acquire(registry, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	captured := registry.AccountingCounters()
	registry.SetUsers(nil)
	registry.PruneAccounting(captured)
	registry.SetUsers([]protocol.User{user})
	current, err := acquire(registry, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	current.Close()
	registry.SetUsers(nil)
	registry.PruneAccounting(captured)
	remaining := registry.AccountingCounters()
	if len(remaining) != 1 || remaining[0].Generation == captured[0].Generation {
		t.Fatalf("stale snapshot retired a fresh generation: %+v", remaining)
	}
}
