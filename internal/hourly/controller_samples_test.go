package hourly

import (
	"errors"
	"testing"
	"time"
)

func TestPruneInactiveSnapshotAndRecreateFreshCounterGeneration(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	f.credit(t, 10)
	p := acquireAdmission(t, f.flow, Upload, 3, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	captured := f.c.Samples()
	f.c.PruneSamples(captured)
	if len(f.c.Samples()) != 1 {
		t.Fatal("pruned current authorized counter")
	}
	f.c.ApplyAuthorization(2, 2, nil)
	f.flow.Close()
	f.c.PruneSamples(captured)
	if len(f.c.Samples()) != 0 {
		t.Fatal("inactive accepted counter retained")
	}
	f.c.ApplyAuthorization(3, 3, []Authorization{{f.binding, f.clock.Now().Add(time.Hour)}})
	flow, err := f.c.OpenFlow(f.binding, func() {})
	if err != nil {
		t.Fatal(err)
	}
	p = acquireAdmission(t, flow, Download, 2, 1)
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	fresh := f.c.Samples()
	if len(fresh) != 1 || fresh[0].CounterGeneration <= captured[0].CounterGeneration || fresh[0].DownloadBytes != 2 {
		t.Fatal(fresh)
	}
	f.c.PruneSamples(captured)
	if len(f.c.Samples()) != 1 {
		t.Fatal("stale capture removed replacement")
	}
}

func TestCapacityFailureLeavesQuotaAndAuthorizationUnchanged(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	f.credit(t, 10)
	f.c.options.MaxPermits = 1
	p := acquireAdmission(t, f.flow, Upload, 5, 1)
	if q, _, err := f.flow.TryAcquire(Download, 5, 1); q != nil || !errors.Is(err, ErrCapacity) {
		t.Fatal(q, err)
	}
	p.Complete(NotHandedOff)
	if f.c.CreditProgress(1)[0].AdmittedUploadBytes != 0 {
		t.Fatal("capacity failure consumed credit")
	}
	f.c.options.MaxOwners = 1
	other := f.binding
	other.Owner.ID = "other-owner"
	third := other
	third.Owner.ID = "third-owner"
	if f.c.ApplyAuthorization(2, 2, []Authorization{{other, f.clock.Now().Add(time.Hour)}, {third, f.clock.Now().Add(time.Hour)}}) {
		t.Fatal("unbounded authorization accepted")
	}
	p = acquireAdmission(t, f.flow, Upload, 10, 1)
	if err := p.Begin(); err != nil {
		t.Fatal("failed publication changed previous authority", err)
	}
	p.Complete(Accepted)
}

func TestAdmissionSamplesAndGrantStopAtUTCMidnight(t *testing.T) {
	f := newAdmissionFixture(t)
	f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, f.clock.Now().Add(48 * time.Hour)}})
	f.clock.Advance(12*time.Hour - time.Second)
	f.grant(t, 1, 0, 0)
	f.credit(t, 10)
	p := acquireAdmission(t, f.flow, Upload, 1, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	f.clock.Advance(time.Second)
	if f.interrupted.Load() != 1 {
		t.Fatal("old-day grant remained live at midnight")
	}
	flow, err := f.c.OpenFlow(f.binding, func() {})
	if err != nil {
		t.Fatal(err)
	}
	f.flow = flow
	f.grant(t, 2, 0, 0)
	if q, _, err := flow.TryAcquire(Download, 1, 1); q != nil || err != nil {
		t.Fatal("old credit crossed midnight", q, err)
	}
	s := f.c.Samples()
	if len(s) != 1 || s[0].DayUTC != "2026-11-09" || s[0].UploadBytes != 1 {
		t.Fatal(s)
	}
}
