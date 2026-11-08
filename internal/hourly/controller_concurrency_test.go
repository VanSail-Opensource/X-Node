package hourly

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentBeginAndCompletionCannotReplayQuota(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	f.credit(t, 100)
	p := acquireAdmission(t, f.flow, Download, 7, 1)
	var begun atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := p.Begin()
			if err == nil {
				begun.Add(1)
			} else if !errors.Is(err, ErrRevoked) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); p.Complete(Uncertain) }()
	}
	wg.Wait()
	if begun.Load() != 1 || f.c.CreditProgress(1)[0].AdmittedDownloadBytes != 7 || f.c.permits.Load() != 0 {
		t.Fatal("replayed permit changed quota or leaked resources")
	}
}

func TestSessionDrainTracksClosedFlowHandoffsAndHooksOutsideLocks(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	f.credit(t, 100)
	p := acquireAdmission(t, f.flow, Upload, 1, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	f.flow.Close()
	drain := f.c.SetSession("44444444444444444444444444444444")
	select {
	case <-drain.Done():
		t.Fatal("logical close hid unfinished native handoff")
	default:
	}
	p.Complete(Accepted)
	select {
	case <-drain.Done():
	default:
		t.Fatal("completion did not drain old session")
	}
}

func TestConcurrentFlowsCannotOverspendSharedCredit(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	f.credit(t, 50)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, _, err := f.flow.TryAcquire(Upload, 1, 1)
			if err != nil {
				t.Error(err)
				return
			}
			if p == nil {
				return
			}
			if err = p.Begin(); err != nil {
				t.Error(err)
				return
			}
			admitted.Add(1)
			p.Complete(Uncertain)
		}()
	}
	wg.Wait()
	if admitted.Load() != 50 || f.c.CreditProgress(1)[0].AdmittedUploadBytes != 50 {
		t.Fatal("concurrent owner quota diverged", admitted.Load())
	}
}

func TestRepeatedCreditFreezeReusesOneUnfinishedDrain(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	f.credit(t, 10)
	p := acquireAdmission(t, f.flow, Upload, 1, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	first, err := f.c.FreezeCredit("credit")
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		next, err := f.c.FreezeCredit("credit")
		if err != nil || next != first {
			t.Fatal("freeze replaced pending drain", err)
		}
	}
	if len(p.drains) != 1 {
		t.Fatal("freeze retries grew native waiters", len(p.drains))
	}
	select {
	case <-first.Done():
		t.Fatal("unfinished handoff was acknowledged")
	default:
	}
	p.Complete(Uncertain)
	select {
	case <-first.Done():
	default:
		t.Fatal("completion failed to close cached drain")
	}
}
