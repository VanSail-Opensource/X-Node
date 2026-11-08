package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func sessionHourlyUser() protocol.User {
	user := testUser()
	paid := time.Now().Add(time.Hour)
	user.AccountingPeriod, user.ValidUntil = "hourly-period", &paid
	user.Hourly = &protocol.HourlyUser{Owner: protocol.HourlyOwner{ID: "owner-one", Generation: 1}, EnrollmentID: "enrollment-one"}
	return user
}

func TestHourlyAdmissionFailsClosedWithoutControllerAndPreservesLegacy(t *testing.T) {
	r := New()
	user := sessionHourlyUser()
	r.SetUsers([]protocol.User{user})
	if lease, err := acquire(r, user, "192.0.2.1", "tcp"); !errors.Is(err, hourly.ErrUnavailable) || lease != nil {
		t.Fatal("hourly identity used ordinary admission without a controller")
	}
	if r.resources != 0 || r.users[user.ID].count != 0 || r.users[user.ID].clients != 0 {
		t.Fatal("failed hourly attachment retained admission reservations")
	}
	user.Hourly = nil
	r.SetUsers([]protocol.User{user})
	lease, err := acquire(r, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if flow, hourlyMode := lease.HourlyFlow(); flow != nil || hourlyMode {
		t.Fatal("legacy lease entered hourly gate")
	}
	lease.Account(true, 7)
	if r.Counters()[user.ID][0] != 7 {
		t.Fatal("legacy counters changed")
	}
}

func TestHourlyTransitRetainsAccountingWithoutAdditionalController(t *testing.T) {
	r, user := New(), sessionHourlyUser()
	binding := protocol.TransitCredential{SourceNodeID: "source", InboundTag: "in", Generation: "route-one", Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440011"}`)}
	user.TransitCredentials = []protocol.TransitCredential{binding}
	r.SetUsers([]protocol.User{user})
	lease, err := r.AcquireTracked(context.Background(), user.ID, protocol.TransitEmail(user.ID, binding), "in", "192.0.2.1", "example.com:443", "udp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Finish()
	defer lease.Close()
	if flow, hourlyMode := lease.HourlyFlow(); flow != nil || hourlyMode {
		t.Fatal("authenticated transit consumed the hourly gate again")
	}
	lease.Account(false, 19)
	if r.Counters()[user.ID][1] != 19 || len(r.AccountingCounters()) != 1 {
		t.Fatal("transit lost existing accounting")
	}
}

func TestHourlyControllerRemovalRevokesWithoutHoldingRegistryLock(t *testing.T) {
	r, user := New(), sessionHourlyUser()
	r.SetHourlyController(hourly.NewController(hourly.Options{}))
	r.SetUsers([]protocol.User{user})
	cancelled := make(chan struct{}, 1)
	lease, err := r.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, func() {
		_ = r.Summary() // Synchronous controller interrupt must not hold Registry.mu.
		cancelled <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Finish()
	flow, hourlyMode := lease.HourlyFlow()
	if flow == nil || !hourlyMode {
		t.Fatal("hourly lease has no controller flow")
	}
	done := make(chan struct{})
	go func() { r.SetHourlyController(nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("controller replacement deadlocked registry")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("native flow was not interrupted")
	}
	if _, _, err = flow.TryAcquire(hourly.Upload, 1, 1); !errors.Is(err, hourly.ErrRevoked) {
		t.Fatal("removed controller retained an admitting flow")
	}
	if fresh, err := acquire(r, user, "192.0.2.1", "tcp"); err == nil {
		fresh.Close()
		t.Fatal("controller removal allowed new hourly traffic")
	}
}
