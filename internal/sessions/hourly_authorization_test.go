package sessions

import (
	"errors"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestHourlyAuthorizationRejectsDelayedPublicationAndCapturesBinding(t *testing.T) {
	r, before := New(), sessionHourlyUser()
	controller := hourly.NewController(hourly.Options{})
	r.SetHourlyController(controller)
	if !r.ApplyAuthorization(state.AuthorizationView{Sequence: 1, Revision: 1, Users: []protocol.User{before}}) {
		t.Fatal("initial authorization rejected")
	}
	lease, err := acquire(r, before, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	oldBinding := *lease.hourlyBinding
	if oldBinding != hourlyBinding(before) {
		t.Fatal("lease did not capture exact owner, generation, enrollment, principal and period")
	}
	r.mu.Lock()
	delayed := r.hourlyPublication()
	r.mu.Unlock()
	after := protocol.Clone(before)
	after.Hourly.Owner.Generation++
	after.Hourly.EnrollmentID, after.AccountingPeriod = "enrollment-two", "hourly-period-two"
	done := make(chan struct{})
	go func() {
		r.ApplyAuthorization(state.AuthorizationView{Sequence: 2, Revision: 2, Users: []protocol.User{after}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("authorization interrupt deadlocked registry")
	}
	delayed.apply()
	if *lease.hourlyBinding != oldBinding || !lease.closed {
		t.Fatal("existing lease changed hourly financial identity")
	}
	if flow, err := controller.OpenFlow(oldBinding, func() {}); !errors.Is(err, hourly.ErrRevoked) {
		if flow != nil {
			flow.Close()
		}
		t.Fatal("delayed snapshot restored old hourly authorization")
	}
	fresh, err := acquire(r, after, "192.0.2.1", "udp")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if *fresh.hourlyBinding != hourlyBinding(after) {
		t.Fatal("fresh session retained previous financial binding")
	}
}

func TestHourlySameBindingRenewalKeepsExistingLease(t *testing.T) {
	r, user := New(), sessionHourlyUser()
	r.SetHourlyController(hourly.NewController(hourly.Options{}))
	r.SetUsers([]protocol.User{user})
	lease, err := acquire(r, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	renewed := protocol.Clone(user)
	paid := renewed.ValidUntil.Add(time.Hour)
	renewed.ValidUntil = &paid
	r.SetUsers([]protocol.User{renewed})
	flow, hourlyMode := lease.HourlyFlow()
	if lease.closed || !hourlyMode || flow == nil {
		t.Fatal("paid-through extension needlessly replaced the flow")
	}
	if _, _, err = flow.TryAcquire(hourly.Upload, 1, 1); err != nil {
		t.Fatal("renewal revoked unchanged hourly binding", err)
	}
}

func TestHourlyRejectedPublicationClosesExistingAndDeniesNewFlows(t *testing.T) {
	r, user := New(), sessionHourlyUser()
	controller := hourly.NewController(hourly.Options{MaxOwners: 1})
	r.SetHourlyController(controller)
	r.SetUsers([]protocol.User{user})
	lease, err := acquire(r, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	other := protocol.Clone(user)
	other.ID, other.UUID = 2, "550e8400-e29b-41d4-a716-446655440099"
	other.Hourly.Owner.ID = "owner-two"
	r.SetUsers([]protocol.User{user, other}) // The controller deliberately cannot accept a second owner.
	if !lease.closed || r.hourlyApplied == r.hourlySequence {
		t.Fatal("rejected controller authorization left existing ingress enabled")
	}
	for _, candidate := range []protocol.User{user, other} {
		if fresh, err := acquire(r, candidate, "192.0.2.1", "udp"); !errors.Is(err, hourly.ErrUnavailable) {
			if fresh != nil {
				fresh.Close()
			}
			t.Fatal("rejected publication used stale controller authorization")
		}
	}
}
