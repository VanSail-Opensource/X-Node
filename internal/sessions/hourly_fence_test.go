package sessions

import (
	"context"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestHourlyTransportFenceRunsOnlyForControllerRevocation(t *testing.T) {
	r, user := New(), sessionHourlyUser()
	controller := hourly.NewController(hourly.Options{})
	controller.SetSession("11111111111111111111111111111111")
	r.SetHourlyController(controller)
	r.SetUsers([]protocol.User{user})
	fenced := 0
	open := func() *Lease {
		t.Helper()
		lease, err := r.AcquireTrackedWithTransportFence(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil, func() {
			_ = r.Summary() // The callback must run outside Registry.mu.
			fenced++
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(lease.Finish)
		t.Cleanup(lease.Close)
		return lease
	}
	first, sibling := open(), open()
	first.Close()
	if fenced != 0 || r.Summary().TotalConnections[user.ID] != 1 {
		t.Fatal("normal completion fenced its authenticated transport sibling")
	}
	controller.ApplyAuthorization(100, 100, nil)
	if fenced != 1 || r.Summary().TotalConnections[user.ID] != 0 {
		t.Fatal("controller revocation did not fence the remaining hourly transport")
	}
	sibling.Close()
	if fenced != 1 {
		t.Fatal("ordinary close repeated transport fencing")
	}
}

func TestOrdinaryTrackedLeaseDoesNotFenceOnNormalClose(t *testing.T) {
	r, user := New(), testUser()
	r.SetUsers([]protocol.User{user})
	fenced := false
	lease, err := r.AcquireTrackedWithTransportFence(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil, func() { fenced = true })
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
	lease.Finish()
	if fenced {
		t.Fatal("ordinary completion interrupted its native transport")
	}
}

func TestHourlyAndRegistryRevocationShareNativeFence(t *testing.T) {
	r, user := New(), sessionHourlyUser()
	controller := hourly.NewController(hourly.Options{})
	controller.SetSession("11111111111111111111111111111111")
	r.SetHourlyController(controller)
	r.SetUsers([]protocol.User{user})
	fenced := 0
	lease, err := r.AcquireTrackedWithTransportFence(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil, func() { fenced++ })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Finish()
	defer lease.Close()
	r.SetUsers(nil)
	if fenced != 1 || !lease.closed {
		t.Fatalf("combined authorization revocation fenced the native transport %d times", fenced)
	}
}
