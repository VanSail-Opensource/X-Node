package hourly

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestOwnerCreditsAndSamplesShareBothDirectionsAcrossIdentities(t *testing.T) {
	f := newAdmissionFixture(t)
	other := f.binding
	other.PrincipalID = 2
	other.PeriodID = "second-period"
	other.EnrollmentID = "second-enrollment"
	if !f.c.ApplyAuthorization(2, 2, []Authorization{{f.binding, f.clock.Now().Add(time.Hour)}, {other, f.clock.Now().Add(time.Hour)}}) {
		t.Fatal("second identity rejected")
	}
	flow, err := f.c.OpenFlow(other, func() {})
	if err != nil {
		t.Fatal(err)
	}
	f.grant(t, 1, 0, 0)
	store, installed := f.credit(t, 12)
	upload := acquireAdmission(t, f.flow, Upload, 5, 1)
	if err = upload.Begin(); err != nil {
		t.Fatal(err)
	}
	upload.Complete(Uncertain)
	upload.Complete(Accepted)
	download := acquireAdmission(t, flow, Download, 7, 1)
	if err = download.Begin(); err != nil {
		t.Fatal(err)
	}
	download.Complete(Uncertain)
	if err = f.c.InstallCredit(installed); err != nil {
		t.Fatal(err)
	}
	if p, _, err := flow.TryAcquire(Upload, 1, 1); err != nil || p != nil {
		t.Fatal("duplicate install restored consumed credit", err)
	}
	progress := f.c.CreditProgress(128)
	if len(progress) != 1 || progress[0].AdmittedUploadBytes != 5 || progress[0].AdmittedDownloadBytes != 7 {
		t.Fatal(progress)
	}
	samples := f.c.Samples()
	if len(samples) != 2 || samples[0].UploadBytes != 5 || samples[1].DownloadBytes != 7 {
		t.Fatal(samples)
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
	if err != nil || proof.UnusedBytes != 0 || proof.UnknownBytes != 0 {
		t.Fatal(proof, err)
	}
	if err = f.c.ForgetCredit(proof); err != nil {
		t.Fatal(err)
	}
	if len(f.c.CreditIDs()) != 0 || len(f.c.Samples()) != 2 {
		t.Fatal("credit cleanup erased samples")
	}
	if err = f.c.InstallCredit(installed); !errors.Is(err, ErrRevoked) {
		t.Fatal("forgotten marker replayed", err)
	}
}

func TestOnlySuccessfulBeginConsumesQuotaAndZeroPacketNeedsPermission(t *testing.T) {
	f := newAdmissionFixture(t)
	if p, _, err := f.flow.TryAcquire(Download, 0, 0); err != nil || p != nil {
		t.Fatal("zero datagram bypassed absent grant", err)
	}
	f.grant(t, 1, 0, 0)
	f.credit(t, 10)
	p := acquireAdmission(t, f.flow, Download, 10, 1)
	p.Complete(NotHandedOff)
	if len(f.c.Samples()) != 0 || f.c.CreditProgress(1)[0].AdmittedDownloadBytes != 0 {
		t.Fatal("reservation counted as usage")
	}
	zero := acquireAdmission(t, f.flow, Download, 0, 0)
	if err := zero.Begin(); err != nil {
		t.Fatal(err)
	}
	zero.Complete(Accepted)
	if len(f.c.Samples()) != 0 {
		t.Fatal("zero packet fabricated usage")
	}
	p = acquireAdmission(t, f.flow, Download, 10, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := p.Begin(); !errors.Is(err, ErrRevoked) {
		t.Fatal("Begin counted twice", err)
	}
	p.Complete(NotHandedOff)
	if got := f.c.CreditProgress(1)[0].AdmittedDownloadBytes; got != 10 {
		t.Fatal("post-admission completion refunded quota", got)
	}
}

func TestCreditStoreInvalidationFencesUnstartedPermit(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	store, _ := f.credit(t, 10)
	p := acquireAdmission(t, f.flow, Upload, 10, 1)
	_ = store.Close()
	if err := p.Begin(); !errors.Is(err, ErrRevoked) {
		t.Fatal("invalidated durable marker admitted", err)
	}
	if len(f.c.Samples()) != 0 {
		t.Fatal("rejected permit counted")
	}
}

func TestCreditProgressFrameLimitAndStableScope(t *testing.T) {
	f := newAdmissionFixture(t)
	f.grant(t, 1, 0, 0)
	f.credit(t, 10)
	p := acquireAdmission(t, f.flow, Upload, 1, 1)
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(Accepted)
	if err := protocol.ValidateHourlyProgress(f.c.CreditProgress(1)[0]); err != nil {
		t.Fatal(err)
	}
	f.c.SetSession("44444444444444444444444444444444")
	if len(f.c.CreditIDs()) != 1 || f.c.CreditProgress(1)[0].AdmittedUploadBytes != 1 {
		t.Fatal("session reset erased financial proof")
	}
}
