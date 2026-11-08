package hourly

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionPauseCancelsTicketsAndRequiresFreshGrantAndCredit(t *testing.T) {
	f := newAdmissionFixture(t)
	oldGrant := f.grant(t, 1, 1000, 100)
	store, oldCredit := f.credit(t, 10)
	f.clock.Advance(100 * time.Millisecond)
	ticket := acquireAdmission(t, f.flow, Upload, 20, 1)
	f.c.SetSession("44444444444444444444444444444444")
	if err := ticket.Begin(); !errors.Is(err, ErrRevoked) || f.interrupted.Load() != 0 || len(f.c.Samples()) != 0 {
		t.Fatal("session change admitted a stale ticket or disconnected idle flow", err)
	}
	if p, _, err := f.flow.TryAcquire(Upload, 1, 1); p != nil || err != nil {
		t.Fatal("new control session bypassed a fresh grant", err)
	}
	grant := f.grant(t, 1, 1000, 100)
	if grant.Nonce == oldGrant.Nonce {
		t.Fatal("new session reused its demand nonce")
	}
	if p, wait, err := f.flow.TryAcquire(Upload, 1, 1); p != nil || err != nil || wait.After <= 0 {
		t.Fatal("new session restored old credit or minted a burst", err)
	}
	if err := f.c.InstallCredit(oldCredit); !errors.Is(err, ErrRevoked) {
		t.Fatal("old-session credit replay became spendable", err)
	}
	install := creditFixtureInstall(2)
	install.ReservationID, install.SessionID, install.ByteCeiling = "fresh-credit", grant.SessionID, 3
	token, err := store.Install(context.Background(), install)
	if err != nil || f.c.InstallCredit(token) != nil {
		t.Fatal("fresh session credit could not be installed", err)
	}
	p := acquireAdmission(t, f.flow, Download, 3, 1)
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	if f.c.CreditProgress(128)[0].AdmittedUploadBytes != 0 || len(f.c.Samples()) != 1 || f.c.Samples()[0].DownloadBytes != 3 {
		t.Fatal("session replay fabricated or lost admissions")
	}
}

func TestIdleGrantExpiryAndShrinkPreserveFlowWithoutNewCapacity(t *testing.T) {
	f := newAdmissionFixture(t)
	grant := f.grant(t, 1, 1000, 100)
	f.clock.Advance(100 * time.Millisecond)
	ticket := acquireAdmission(t, f.flow, Upload, 20, 1)
	grant.Sequence, grant.RateBytesPerSecond, grant.BurstBytes = 2, 500, 50
	grant.Nonce = f.c.PendingDemand(1)[0].Nonce
	drain, err := f.c.ApplyGrant(grant)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-drain.Done():
	default:
		t.Fatal("idle shrink waited for a nonexistent started handoff")
	}
	if err = ticket.Begin(); !errors.Is(err, ErrRevoked) || f.interrupted.Load() != 0 {
		t.Fatal("idle shrink restored an old ticket or disconnected flow", err)
	}
	f.clock.Advance(10 * time.Second)
	if p, _, err := f.flow.TryAcquire(Upload, 1, 1); p != nil || err != nil || f.interrupted.Load() != 0 {
		t.Fatal("expired grant did not pause the existing idle flow", err)
	}
	f.grant(t, 3, 1000, 100)
	if p, _, err := f.flow.TryAcquire(Upload, 1, 1); p != nil || err != nil {
		t.Fatal("fresh grant retroactively refilled expired time", err)
	}
}
