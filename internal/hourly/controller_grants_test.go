package hourly

import (
	"errors"
	"testing"
	"time"
)

func TestDemandReplayCannotExtendOriginalDeadline(t *testing.T) {
	f := newAdmissionFixture(t)
	_, _, _ = f.flow.TryAcquire(Upload, 1, 1)
	original := f.c.PendingDemand(1)[0]
	f.clock.Advance(9 * time.Second)
	repeated := f.c.PendingDemand(1)[0]
	if repeated.Nonce != original.Nonce {
		t.Fatal("pending nonce was replaced before expiry")
	}
	g := f.grant(t, 1, 0, 0)
	f.clock.Advance(time.Second)
	if f.interrupted.Load() != 0 {
		t.Fatal("grant deadline disconnected an idle flow")
	}
	if _, err := f.c.ApplyGrant(g); !errors.Is(err, ErrRevoked) {
		t.Fatal("expired replay restored permission", err)
	}
	if p, _, err := f.flow.TryAcquire(Upload, 1, 1); p != nil || err != nil {
		t.Fatal("expired grant did not pause existing flow", err)
	}
}

func TestShrinkWaitsForInterruptAndStartedHandoffOutsideLocks(t *testing.T) {
	f := newAdmissionFixture(t)
	flow, err := f.c.OpenFlow(f.binding, func() { f.c.CreditProgress(128); f.flow.Close() })
	if err != nil {
		t.Fatal(err)
	}
	g := f.grant(t, 1, 1000, 100)
	f.credit(t, 10)
	f.clock.Advance(time.Millisecond)
	p := acquireAdmission(t, flow, Download, 11, 1)
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	// The handoff consumed all credit and one reduced-rate byte. Earn the
	// probe's one byte before reserving it; the rate-bound handoff must drain.
	f.clock.Advance(time.Millisecond)
	probe := acquireAdmission(t, f.flow, Upload, 1, 1)
	probe.Complete(NotHandedOff)
	g.Nonce = f.c.PendingDemand(1)[0].Nonce
	g.Sequence = 2
	g.RateBytesPerSecond = 500
	g.BurstBytes = 50
	drain, err := f.c.ApplyGrant(g)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-drain.Done():
		t.Fatal("shrink acknowledged unfinished native handoff")
	default:
	}
	duplicate, err := f.c.ApplyGrant(g)
	if err != nil || duplicate != drain {
		t.Fatal("duplicate replaced original shrink drain", err)
	}
	select {
	case <-duplicate.Done():
		t.Fatal("duplicate acknowledged unfinished shrink")
	default:
	}
	if !flow.fenced {
		t.Fatal("shrink did not fence started native flow")
	}
	if p.finished {
		t.Fatal("shrink invented native completion")
	}
	p.Complete(Uncertain)
	select {
	case <-drain.Done():
	default:
		t.Fatal("finished native handoff did not release shrink")
	}
	if f.c.CreditProgress(1)[0].AdmittedDownloadBytes != 10 {
		t.Fatal("shrink refunded admitted credit")
	}
}

func TestSessionPausesIdleFlowAndPaidExpiryInterrupts(t *testing.T) {
	t.Run("session", func(t *testing.T) {
		f := newAdmissionFixture(t)
		drain := f.c.SetSession("44444444444444444444444444444444")
		select {
		case <-drain.Done():
		default:
			t.Fatal("idle session admission barrier did not complete")
		}
		if f.interrupted.Load() != 0 {
			t.Fatal("session reset disconnected an idle flow")
		}
		if p, _, err := f.flow.TryAcquire(Upload, 1, 1); p != nil || err != nil {
			t.Fatal("new session did not pause for a fresh grant", err)
		}
	})
	t.Run("paid", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, f.clock.Now().Add(time.Second)}})
		f.clock.Advance(time.Second)
		if f.interrupted.Load() != 1 {
			t.Fatal("paid boundary waited for actor tick")
		}
	})
}

func TestGrantSequenceAndSessionAreFenced(t *testing.T) {
	f := newAdmissionFixture(t)
	g := f.grant(t, 1, 1, 1)
	if _, err := f.c.ApplyGrant(g); err != nil {
		t.Fatal("identical live replay rejected", err)
	}
	g.RateBytesPerSecond++
	if _, err := f.c.ApplyGrant(g); !errors.Is(err, ErrRevoked) {
		t.Fatal("changed same-sequence grant applied", err)
	}
	g.SessionID = "44444444444444444444444444444444"
	if _, err := f.c.ApplyGrant(g); !errors.Is(err, ErrRevoked) {
		t.Fatal("wrong session grant applied", err)
	}
}

func TestExpiredGrantCannotBeReplayedBeforeTimerCallbackRuns(t *testing.T) {
	f := newAdmissionFixture(t)
	grant := f.grant(t, 1, 100, 10)
	// Simulate a delayed timer callback without running the fake timer worker.
	f.clock.mu.Lock()
	f.clock.now = f.clock.now.Add(10 * time.Second)
	f.clock.mu.Unlock()
	if _, err := f.c.ApplyGrant(grant); !errors.Is(err, ErrRevoked) {
		t.Fatal("expired grant replay acknowledged", err)
	}
	if f.interrupted.Load() != 0 {
		t.Fatal("expired replay disconnected an idle flow")
	}
}
