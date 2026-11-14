package hourly

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReservedCreditContinuesAfterRateGrantExpiryWithoutExtendingRate(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 1000, 100)
	store, _ := f.credit(t, 17)
	f.clock.Advance(11 * time.Second)
	p := acquireAdmission(t, f.flow, Download, 23, 1)
	if p.Bytes() != 17 || p.grant != nil || p.reduced != 0 {
		t.Fatal("offline admission borrowed expired rate capacity")
	}
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Uncertain)
	if next, wait, err := f.flow.TryAcquire(Upload, 1, 1); next != nil || err != nil || wait.After != 0 {
		t.Fatal("credit exhaustion reused an expired reduced-rate grant", err)
	}
	drain, err := f.c.FreezeCredit("credit")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := f.c.PrepareSeal(drain)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.Seal(context.Background(), candidate)
	if err != nil || proof.AdmittedDownloadBytes != 17 || proof.UnusedBytes != 0 || proof.UnknownBytes != 0 {
		t.Fatal("offline usage lost exact financial evidence", proof, err)
	}
}

func TestCreditOnlyHandoffSurvivesRateExpiryAndStillExpiresWhenUnpaid(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 1000, 100)
	f.credit(t, 17)
	p := acquireAdmission(t, f.flow, Download, 10, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(11 * time.Second)
	if f.interrupted.Load() != 0 || p.finished || p.flow.fenced {
		t.Fatal("rate lease expiry interrupted fully reserved payload")
	}
	f.clock.Advance(time.Hour)
	if f.interrupted.Load() != 1 || !p.flow.fenced {
		t.Fatal("offline credit bypassed the purchased expiry")
	}
	p.Complete(Uncertain)
	if f.c.CreditProgress(1)[0].AdmittedDownloadBytes != 10 {
		t.Fatal("expiry refunded admitted payload")
	}
}

func TestCreditOnlyAdmissionPreservesDatagramAndAuthorityBoundaries(t *testing.T) {
	for _, boundary := range []string{"session", "paid", "midnight", "freeze", "health"} {
		t.Run(boundary, func(t *testing.T) {
			f := newAdmissionFixture(t)
			store, _ := f.credit(t, 5)
			if p, _, err := f.flow.TryAcquire(Upload, 8, 8); p != nil || err != nil {
				t.Fatal("offline credit split an atomic datagram", err)
			}
			p := acquireAdmission(t, f.flow, Upload, 5, 1)
			switch boundary {
			case "session":
				f.c.SetSession("44444444444444444444444444444444")
			case "paid":
				f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, f.clock.Now()}})
			case "midnight":
				// Keep paid authorization valid beyond the day boundary so the
				// day check, rather than purchased expiry, rejects this permit.
				f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, f.clock.Now().Add(24 * time.Hour)}})
				// Bypass timer callbacks to prove Begin itself checks the day.
				f.clock.mu.Lock()
				f.clock.now = f.clock.now.Add(12 * time.Hour)
				f.clock.mu.Unlock()
			case "freeze":
				if _, err := f.c.FreezeCredit("credit"); err != nil {
					t.Fatal(err)
				}
			case "health":
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.Begin(); !errors.Is(err, ErrRevoked) {
				t.Fatal("offline credit crossed an authority boundary", err)
			}
			if len(f.c.Samples()) != 0 || f.c.CreditProgress(1)[0].AdmittedUploadBytes != 0 {
				t.Fatal("rejected admission consumed credit")
			}
		})
	}
}

func TestStartedCreditHandoffUsesRenewedPaidBoundaryWithinOriginalDay(t *testing.T) {
	for _, boundary := range []string{"paid", "midnight"} {
		t.Run(boundary, func(t *testing.T) {
			f := newAdmissionFixture(t)
			f.credit(t, 17)
			start := f.clock.Now()
			p := acquireAdmission(t, f.flow, Download, 10, 1)
			if err := p.Begin(); err != nil {
				t.Fatal(err)
			}
			f.clock.Advance(30 * time.Minute)
			paid, finish := start.Add(2*time.Hour), 2*time.Hour
			if boundary == "midnight" {
				paid, finish = start.Add(24*time.Hour), 12*time.Hour
			}
			if !f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, paid}}) {
				t.Fatal("paid renewal was rejected")
			}
			f.clock.Advance(30 * time.Minute) // The permit's former paid deadline.
			if f.interrupted.Load() != 0 || f.flow.fenced || p.finished {
				t.Fatal("stale paid deadline interrupted renewed credit handoff")
			}
			if progress := f.c.CreditProgress(1)[0]; progress.AdmittedDownloadBytes != 10 {
				t.Fatal("renewal changed already consumed credit", progress)
			}
			f.clock.Advance(finish - time.Hour)
			if f.interrupted.Load() != 1 || !f.flow.fenced {
				t.Fatal("renewal escaped its paid or original UTC-day bound")
			}
			p.Complete(Uncertain)
			if progress := f.c.CreditProgress(1)[0]; progress.AdmittedDownloadBytes != 10 {
				t.Fatal("handoff expiry refunded consumed bytes", progress)
			}
		})
	}
}

func TestPaidRenewalCannotExtendStartedHandoffsOriginalRateGrant(t *testing.T) {
	f := newAdmissionFixture(t)
	if !f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, f.clock.Now().Add(2 * time.Second)}}) {
		t.Fatal("short paid authorization was rejected")
	}
	f.grant(t, 1, 1000, 100)
	f.clock.Advance(time.Millisecond)
	p := acquireAdmission(t, f.flow, Download, 1, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Second)
	if !f.c.ApplyAuthorization(3, 3, []Authorization{{f.binding, f.clock.Now().Add(time.Hour)}}) {
		t.Fatal("paid renewal was rejected")
	}
	f.clock.Advance(time.Second)
	if f.interrupted.Load() != 0 || f.flow.fenced {
		t.Fatal("stale paid deadline interrupted a still-valid rate grant")
	}
	f.clock.Advance(8 * time.Second)
	if f.interrupted.Load() != 1 || !f.flow.fenced {
		t.Fatal("paid renewal extended the original ten-second rate lease")
	}
	p.Complete(Uncertain)
}
