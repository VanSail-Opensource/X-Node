package hourly

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type admissionTimer struct {
	at      time.Time
	fn      func()
	stopped atomic.Bool
}

func (t *admissionTimer) Stop() bool { return !t.stopped.Swap(true) }

type admissionClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*admissionTimer
}

func (c *admissionClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *admissionClock) After(d time.Duration, fn func()) Stopper {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &admissionTimer{at: c.now.Add(d), fn: fn}
	c.timers = append(c.timers, t)
	return t
}
func (c *admissionClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var next *admissionTimer
		for _, timer := range c.timers {
			if !timer.at.After(c.now) && timer.stopped.CompareAndSwap(false, true) {
				next = timer
				break
			}
		}
		c.mu.Unlock()
		if next == nil {
			return
		}
		next.fn()
	}
}

type admissionFixture struct {
	c           *Controller
	clock       *admissionClock
	binding     BindingKey
	flow        *Flow
	interrupted atomic.Int64
	nonce       atomic.Uint64
}

func newAdmissionFixture(t *testing.T) *admissionFixture {
	t.Helper()
	f := &admissionFixture{clock: &admissionClock{now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}, binding: BindingKey{Owner: OwnerKey{ID: "account", Generation: 7}, EnrollmentID: "enrollment", PeriodID: "period", PrincipalID: 1}}
	f.c = NewController(Options{Now: f.clock.Now, AfterFunc: f.clock.After, Nonce: func() string { return fmt.Sprintf("%032x", f.nonce.Add(1)) }})
	if !f.c.ApplyAuthorization(1, 1, []Authorization{{Key: f.binding, PaidThrough: f.clock.Now().Add(time.Hour)}}) {
		t.Fatal("authorization rejected")
	}
	f.c.SetSession("33333333333333333333333333333333")
	var err error
	f.flow, err = f.c.OpenFlow(f.binding, func() { f.interrupted.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *admissionFixture) grant(t *testing.T, sequence, rate uint64, burst uint32) protocol.HourlyGrant {
	t.Helper()
	p, _, err := f.flow.TryAcquire(Upload, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		p.Complete(NotHandedOff)
	}
	demands := f.c.PendingDemand(128)
	if len(demands) != 1 {
		t.Fatalf("demand missing: %#v", demands)
	}
	g := protocol.HourlyGrant{SessionID: f.c.session, Owner: demands[0].Owner, Nonce: demands[0].Nonce, Sequence: sequence, DayUTC: f.clock.Now().UTC().Format(time.DateOnly), LifetimeMillis: 10000, RateBytesPerSecond: rate, BurstBytes: burst}
	if _, err = f.c.ApplyGrant(g); err != nil {
		t.Fatal(err)
	}
	return g
}
func (f *admissionFixture) credit(t *testing.T, bytes uint64) (*CreditStore, InstalledCredit) {
	t.Helper()
	store, _ := openCreditFixture(t)
	i := creditFixtureInstall(1)
	i.ByteCeiling = bytes
	installed, err := store.Install(context.Background(), i)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.c.InstallCredit(installed); err != nil {
		t.Fatal(err)
	}
	return store, installed
}
func acquireAdmission(t *testing.T, flow *Flow, direction Direction, bytes, atomicBytes int) *Permit {
	t.Helper()
	p, _, err := flow.TryAcquire(direction, bytes, atomicBytes)
	if err != nil || p == nil {
		t.Fatalf("permit missing: %v", err)
	}
	return p
}
