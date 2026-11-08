package hourly

import (
	"testing"
	"time"
)

func TestReducedBucketStartsEmptyAndSharesBothDirections(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 100, 10)
	if p, wait, err := f.flow.TryAcquire(Upload, 10, 1); err != nil || p != nil || wait.After == 0 {
		t.Fatal("fresh bucket minted burst", err)
	}
	f.clock.Advance(100 * time.Millisecond)
	p := acquireAdmission(t, f.flow, Upload, 10, 1)
	f.clock.Advance(100 * time.Millisecond)
	if q, _, err := f.flow.TryAcquire(Download, 1, 1); err != nil || q != nil {
		t.Fatal("held reservation allowed another burst", err)
	}
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	if q, _, err := f.flow.TryAcquire(Download, 1, 1); err != nil || q != nil {
		t.Fatal("held time accumulated fresh burst", err)
	}
	f.clock.Advance(100 * time.Millisecond)
	q := acquireAdmission(t, f.flow, Download, 10, 1)
	if err := q.Begin(); err != nil {
		t.Fatal(err)
	}
	q.Complete(Accepted)
	s := f.c.Samples()
	if len(s) != 1 || s[0].UploadBytes != 10 || s[0].DownloadBytes != 10 {
		t.Fatal(s)
	}
}

func TestGrantRefreshAndLargeRateCannotMintOrOverflowBurst(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 100, 10)
	f.clock.Advance(100 * time.Millisecond)
	p := acquireAdmission(t, f.flow, Upload, 5, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	f.grant(t, 2, 100, 20)
	p = acquireAdmission(t, f.flow, Upload, 20, 1)
	if p.Bytes() != 5 {
		t.Fatal("refresh granted a new burst", p.Bytes())
	}
	p.Complete(NotHandedOff)
	f.grant(t, 3, 1_000_000_000_000, 16384)
	f.clock.Advance(time.Second)
	p = acquireAdmission(t, f.flow, Upload, 1<<20, 1)
	if p.Bytes() != 16384 {
		t.Fatal("large rate overflowed/clamped handoff incorrectly", p.Bytes())
	}
	p.Complete(NotHandedOff)
}

func TestAtomicPacketWaitsRatherThanSplittingToAvailableRemainder(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 8192, 8192)
	f.clock.Advance(500 * time.Millisecond)
	if p, wait, err := f.flow.TryAcquire(Download, 8192, 8192); err != nil || p != nil || wait.After != 500*time.Millisecond {
		t.Fatal("split atomic datagram", wait, err)
	}
	f.clock.Advance(500 * time.Millisecond)
	p := acquireAdmission(t, f.flow, Download, 8192, 8192)
	if p.Bytes() != 8192 {
		t.Fatal(p.Bytes())
	}
	p.Complete(NotHandedOff)
}

func TestDelayedHeldPermitCannotRefillNewlyFreedBurstRetroactively(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 100, 10)
	f.clock.Advance(100 * time.Millisecond)
	p := acquireAdmission(t, f.flow, Upload, 10, 1)
	// No intervening TryAcquire settles the clock while capacity is held.
	f.clock.Advance(500 * time.Millisecond)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	if next, _, err := f.flow.TryAcquire(Download, 10, 1); next != nil || err != nil {
		t.Fatal("held time minted a second burst", next, err)
	}
}
