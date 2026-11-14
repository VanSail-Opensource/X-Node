package hourly

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestShutdownFencePreservesAdmittedBytesWithoutNativeHandoffWait(t *testing.T) {
	f := newAdmissionFixture(t)
	store, credit := f.credit(t, 1000)
	started := acquireAdmission(t, f.flow, Upload, 7, 1)
	if err := started.Begin(); err != nil {
		t.Fatal(err)
	}
	defer started.Complete(Uncertain)
	unstarted := acquireAdmission(t, f.flow, Download, 11, 1)
	f.c.StopAdmission()
	// A transport callback or a late configuration publish cannot reopen the
	// process after its irreversible financial shutdown fence.
	f.c.SetSession(credit.install.SessionID)
	if f.c.ApplyAuthorization(2, 2, []Authorization{{Key: f.binding, PaidThrough: f.clock.Now().Add(time.Second)}}) {
		t.Fatal("shutdown accepted a later authorization publication")
	}
	if _, err := f.c.OpenFlow(f.binding, func() {}); !errors.Is(err, ErrRevoked) {
		t.Fatal("shutdown admitted a new flow", err)
	}
	if err := f.c.InstallCredit(credit); !errors.Is(err, ErrRevoked) {
		t.Fatal("shutdown accepted credit activation", err)
	}
	grant := protocol.HourlyGrant{SessionID: credit.install.SessionID, Owner: credit.install.Owner, Nonce: "44444444444444444444444444444444", Sequence: 1, DayUTC: credit.install.DayUTC, LifetimeMillis: 10000}
	if _, err := f.c.ApplyGrant(grant); !errors.Is(err, ErrRevoked) {
		t.Fatal("shutdown accepted a grant", err)
	}
	if p, _, err := f.flow.TryAcquire(Upload, 1, 1); p != nil || !errors.Is(err, ErrRevoked) {
		t.Fatal("existing flow acquired after the shutdown fence", err)
	}
	drain, err := f.c.FreezeCredit(credit.install.ReservationID)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-drain.Done():
	default:
		t.Fatal("financial seal waited for an already-admitted native write")
	}
	if err = unstarted.Begin(); !errors.Is(err, ErrRevoked) {
		t.Fatal("unstarted reservation escaped shutdown", err)
	}
	candidate, err := f.c.PrepareSeal(drain)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := store.SealBatch(context.Background(), []SealCandidate{candidate})
	if err != nil || len(proofs) != 1 || proofs[0].AdmittedUploadBytes != 7 || proofs[0].AdmittedDownloadBytes != 0 || proofs[0].UnusedBytes != 993 || proofs[0].UnknownBytes != 0 || f.interrupted.Load() != 0 {
		t.Fatal("shutdown waited for delivery or changed financial totals", proofs, err)
	}
	if err = f.c.ForgetCredit(proofs[0]); err != nil {
		t.Fatal(err)
	}
	started.Complete(Uncertain)
	if retained := store.Recovery(); len(retained) != 1 || retained[0] != proofs[0] {
		t.Fatal("late native completion changed a sealed proof", retained)
	}
}

func TestShutdownFenceLinearizesConcurrentBeginBeforeExactSeal(t *testing.T) {
	f := newAdmissionFixture(t)
	store, credit := f.credit(t, 1000)
	var permits []*Permit
	for range 64 {
		permits = append(permits, acquireAdmission(t, f.flow, Download, 1, 1))
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	var admitted atomic.Uint64
	for _, permit := range permits {
		workers.Go(func() {
			<-start
			if err := permit.Begin(); err == nil {
				admitted.Add(1)
			} else if !errors.Is(err, ErrRevoked) {
				t.Error(err)
			}
			permit.Complete(Uncertain)
		})
	}
	close(start)
	f.c.StopAdmission()
	workers.Wait()
	drain, err := f.c.FreezeCredit(credit.install.ReservationID)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := f.c.PrepareSeal(drain)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := store.SealBatch(context.Background(), []SealCandidate{candidate})
	if err != nil || len(proofs) != 1 || proofs[0].AdmittedDownloadBytes != admitted.Load() || proofs[0].UnusedBytes != 1000-admitted.Load() || proofs[0].UnknownBytes != 0 {
		t.Fatal("shutdown raced the synchronous admission boundary", admitted.Load(), proofs, err)
	}
}
