package hourly

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPermitUTCWindowAcrossOffsetsAndClockRewind(t *testing.T) {
	f := newAdmissionFixture(t)
	now := f.clock.Now().In(time.FixedZone("UTC+14", 14*60*60))
	f.c.options.Now = func() time.Time { return now }
	start := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC).In(now.Location())
	f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, now.Add(48 * time.Hour)}})
	f.credit(t, 4)

	// One UTC day begins and ends on different dates in this local zone.
	now = start.Add(24*time.Hour - time.Nanosecond)
	old := acquireAdmission(t, f.flow, Upload, 1, 1)
	held := acquireAdmission(t, f.flow, Download, 1, 1)
	if err := old.Begin(); err != nil {
		t.Fatal(err)
	}
	old.Complete(Accepted)
	now = start.Add(24 * time.Hour)
	if err := held.Begin(); !errors.Is(err, ErrRevoked) {
		t.Fatal("old day permit not rejected at midnight", err)
	}
	if permit, _, err := f.flow.TryAcquire(Download, 1, 1); permit != nil || err != nil {
		t.Fatal("credit crossed midnight", permit, err)
	}
	now = start
	held = acquireAdmission(t, f.flow, Download, 1, 1)
	now = start.Add(-time.Nanosecond)
	if err := held.Begin(); !errors.Is(err, ErrRevoked) {
		t.Fatal("permit accepted before its UTC day", err)
	}
	samples := f.c.Samples()
	if len(samples) != 1 || samples[0].DayUTC != "2026-11-09" || samples[0].UploadBytes != 1 || samples[0].DownloadBytes != 0 {
		t.Fatalf("unexpected usage: %+v", samples)
	}
}

func TestPermitSpendsEligibleCreditsInOrder(t *testing.T) {
	f := newAdmissionFixture(t)
	o := f.flow.owner
	store := &CreditStore{}
	store.healthy.Store(true)
	add := func(id, kind string, seq, amount uint64) *creditState {
		return addHotPathFixtureCredit(t, o, store, id, kind, seq, amount)
	}
	extra := add("extra", "extra", 1, 4)
	later := add("later", "free", 4, 2)
	earlier := add("earlier", "free", 3, 3)
	tail := add("tail", "extra", 9, 10)
	add("other-extra", "extra", 10, 10) // Also exercise the larger eligible set.
	add("frozen", "free", 2, 20).frozen = true
	add("invalid", "free", 5, 20).installed.marker.invalidate()
	add("exhausted", "free", 6, 1).admitted[Upload] = 1
	add("old-day", "free", 7, 20).installed.install.DayUTC = "2026-11-08"
	add("old-session", "free", 8, 20).installed.install.SessionID = "old-session"

	p := acquireAdmission(t, f.flow, Upload, 7, 1)
	if earlier.held != 3 || later.held != 2 || extra.held != 2 || tail.held != 0 {
		t.Fatal("did not reserve eligible free credits before extra")
	}
	f.c.creditIndex.Store("later", later)
	if _, err := f.c.FreezeCredit("later"); err != nil {
		t.Fatal(err)
	}
	if err := p.Begin(); !errors.Is(err, ErrRevoked) {
		t.Fatal("freeze did not revoke multi-credit permit", err)
	}
	if earlier.held|later.held|extra.held != 0 {
		t.Fatal("revocation did not return all held credit")
	}
	p = acquireAdmission(t, f.flow, Download, 7, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	if earlier.admitted[Download] != 3 || extra.admitted[Download] != 4 || later.admitted[Download]|tail.admitted[Download] != 0 {
		t.Fatal("handoff did not consume the remaining credits exactly")
	}
	samples := f.c.Samples()
	if len(samples) != 1 || samples[0].UploadBytes != 0 || samples[0].DownloadBytes != 7 {
		t.Fatalf("unexpected usage: %+v", samples)
	}
}

// Provision process-local marker state without timing journal writes.
func addHotPathFixtureCredit(t testing.TB, owner *ownerState, store *CreditStore, id, kind string, seq, amount uint64) *creditState {
	t.Helper()
	install := creditFixtureInstall(seq)
	install.ReservationID, install.Kind, install.ByteCeiling = id, kind, amount
	install.DayUTC = owner.controller.options.Now().UTC().Format(time.DateOnly)
	marker := newCreditMarker(store)
	if !marker.claim() {
		t.Fatal("could not claim benchmark credit")
	}
	credit := &creditState{owner: owner, installed: InstalledCredit{install: install, marker: marker}}
	owner.credits[id] = credit
	return credit
}

func BenchmarkHourlyReservedHandoff(b *testing.B) {
	for _, credits := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("credits=%d", credits), func(b *testing.B) {
			now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
			controller := NewController(Options{Now: func() time.Time { return now }})
			session := creditFixtureInstall(1).SessionID
			binding := BindingKey{Owner: OwnerKey{ID: "account", Generation: 7}, EnrollmentID: "enrollment", PeriodID: "period", PrincipalID: 1}
			controller.SetSession(session)
			if !controller.ApplyAuthorization(1, 1, []Authorization{{binding, now.Add(time.Hour)}}) {
				b.Fatal("authorization")
			}
			flow, err := controller.OpenFlow(binding, func() {})
			if err != nil {
				b.Fatal(err)
			}
			defer flow.Close()
			store := &CreditStore{}
			store.healthy.Store(true)
			for i := range credits {
				kind := "extra"
				if i%2 == 0 {
					kind = "free"
				}
				addHotPathFixtureCredit(b, flow.owner, store, fmt.Sprintf("credit-%d", i), kind, uint64(i+1), 1<<50)
			}
			b.ReportAllocs()
			b.SetBytes(128)
			for b.Loop() {
				permit, _, err := flow.TryAcquire(Download, 128, 1)
				if err != nil || permit == nil {
					b.Fatalf("permit: %v", err)
				}
				if err := permit.Begin(); err != nil {
					b.Fatal(err)
				}
				permit.Complete(Accepted)
			}
		})
	}
}
