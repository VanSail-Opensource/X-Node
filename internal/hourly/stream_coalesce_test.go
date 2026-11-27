package hourly

import (
	"errors"
	"testing"
	"time"
)

func TestReducedStreamCoalescesWithoutSpendingEarly(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 1_000_000, 16384)
	f.clock.Advance(10 * time.Microsecond)
	p, wait, err := f.flow.TryAcquire(Download, 4000, 1)
	if err != nil || p != nil || wait.After != 990*time.Microsecond || wait.Changed == nil {
		t.Fatalf("permit=%v wait=%v err=%v", p, wait, err)
	}
	if len(f.c.Samples()) != 0 {
		t.Fatal("coalescing counted bytes before admission")
	}
	f.clock.Advance(wait.After)
	p = acquireAdmission(t, f.flow, Download, 4000, 1)
	if p.Bytes() != 1000 {
		t.Fatalf("admitted %d, want exactly 1000 refilled bytes", p.Bytes())
	}
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	if s := f.c.Samples(); len(s) != 1 || s[0].DownloadBytes != 1000 || s[0].UploadBytes != 0 {
		t.Fatalf("unexpected accounting: %#v", s)
	}
}

func TestReducedStreamCoalescesWithinGrantAndBurstOnly(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 1_000_000, 64)
	_, wait, err := f.flow.TryAcquire(Upload, 8000, 1)
	if err != nil || wait.After != 64*time.Microsecond {
		t.Fatalf("wait exceeded burst: %+v %v", wait, err)
	}
	f.clock.Advance(64 * time.Microsecond)
	p := acquireAdmission(t, f.flow, Upload, 8000, 1)
	if p.Bytes() != 64 {
		t.Fatalf("permit exceeded burst: %d", p.Bytes())
	}
	p.Complete(NotHandedOff)
	f.clock.Advance(10 * time.Second)
	if q, _, err := f.flow.TryAcquire(Upload, 8000, 1); q != nil || err != nil {
		t.Fatalf("expired grant admitted bytes: %v %v", q, err)
	}
}

func TestReducedStreamDoesNotDelayReservedCreditOrOneByte(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 1_000_000, 16384)
	f.credit(t, 11)
	p := acquireAdmission(t, f.flow, Upload, 4096, 1)
	if p.Bytes() != 11 {
		t.Fatalf("reserved bytes not admitted immediately: %d", p.Bytes())
	}
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	f.clock.Advance(time.Microsecond)
	p = acquireAdmission(t, f.flow, Upload, 1, 1)
	if !f.c.ApplyAuthorization(2, 2, nil) {
		t.Fatal("failed to remove authorization")
	}
	if err := p.Begin(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revocation did not fence unstarted permit: %v", err)
	}
	p.Complete(NotHandedOff)
}
