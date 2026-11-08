package xray

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/xtls/xray-core/common/buf"
)

func TestHourlyFinancialSealDoesNotInterruptBlockedAdmittedWriter(t *testing.T) {
	cfg, _ := testConfig(t)
	_, controller := nativeHourlyRegistry(t, &cfg)
	store, err := hourly.OpenCreditStore(filepath.Join(t.TempDir(), "private", "credits.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u := cfg.Users[0]
	var interrupts atomic.Int64
	flow, err := controller.OpenFlow(hourly.BindingKey{Owner: hourly.OwnerKey{ID: u.Hourly.Owner.ID, Generation: u.Hourly.Owner.Generation}, EnrollmentID: u.Hourly.EnrollmentID, PeriodID: u.AccountingPeriod, PrincipalID: u.ID}, func() { interrupts.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	install := protocol.HourlyCreditInstall{ReservationID: "first-credit", IssueSequence: 1, Owner: u.Hourly.Owner, DayUTC: time.Now().UTC().Format(time.DateOnly), AgentID: nativeHourlySession, BootID: nativeHourlySession, SessionID: nativeHourlySession, ByteCeiling: 1000, Kind: "free"}
	addCredit := func() {
		t.Helper()
		token, err := store.Install(context.Background(), install)
		if err != nil || controller.InstallCredit(token) != nil {
			t.Fatal("cannot install real durable credit", err)
		}
	}
	addCredit()
	_, _, _ = flow.TryAcquire(hourly.Download, 7, 1)
	demand := controller.PendingDemand(1)[0]
	if _, err = controller.ApplyGrant(protocol.HourlyGrant{SessionID: nativeHourlySession, Owner: demand.Owner, Nonce: demand.Nonce, Sequence: 1, DayUTC: install.DayUTC, LifetimeMillis: 10000}); err != nil {
		t.Fatal(err)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	result := make(chan error, 1)
	writeErr := errors.New("constructed post-admission delivery failure")
	sink := hourlyPacketSink(func(mb buf.MultiBuffer) error {
		defer buf.ReleaseMulti(mb)
		close(entered)
		<-release
		return writeErr
	})
	writer := &hourlyWriter{Writer: sink, ctx: context.Background(), acquire: hourlyAcquirer(flow)}
	go func() {
		defer close(finished)
		result <- writer.WriteMultiBuffer(buf.MultiBuffer{nativeHourlyBuffer("pending")})
	}()
	defer func() {
		once.Do(func() { close(release) })
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("blocked native fixture did not finish")
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not cross its real admission boundary")
	}
	drain, err := controller.FreezeCredit(install.ReservationID)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-drain.Done():
	default:
		t.Fatal("financial credit waited for native delivery")
	}
	candidate, err := controller.PrepareSeal(drain)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.Seal(context.Background(), candidate)
	if err != nil || proof.AdmittedDownloadBytes != 7 || proof.UnusedBytes != 993 || proof.UnknownBytes != 0 {
		t.Fatal("blocked delivery changed the exact financial partition", proof, err)
	}
	if err = controller.ForgetCredit(proof); err != nil {
		t.Fatal(err)
	}
	install.ReservationID, install.IssueSequence = "next-credit", 2
	addCredit()
	p, _, err := flow.TryAcquire(hourly.Upload, 3, 1)
	if err != nil || p == nil || p.Begin() != nil {
		t.Fatal("financial sealing revoked the still-authorized flow", err)
	}
	p.Complete(hourly.Accepted)
	if interrupts.Load() != 0 {
		t.Fatal("credit rollover interrupted the native connection")
	}
	once.Do(func() { close(release) })
	if err = <-result; !errors.Is(err, writeErr) {
		t.Fatal("fixture did not preserve uncertain native delivery", err)
	}
	samples := controller.Samples()
	if len(samples) != 1 || samples[0].UploadBytes != 3 || samples[0].DownloadBytes != 7 || store.Recovery()[0] != proof {
		t.Fatal("late writer completion changed admitted quota or its immutable proof")
	}
}
