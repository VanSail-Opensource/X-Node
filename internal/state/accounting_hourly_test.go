package state

import (
	"math"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func hourlyHistoryFixture() protocol.HourlySample {
	at := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	return protocol.HourlySample{CounterGeneration: 1, Owner: protocol.HourlyOwner{ID: "account", Generation: 2}, EnrollmentID: "hourly", UserID: 7, AccountingPeriod: "paid", DayUTC: "2026-11-09", From: at, Through: at, UploadBytes: 5}
}

func TestAccountingCaptureRetryCannotPartiallyAppendHourlyOrNative(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	history := hourlyHistoryFixture()
	native := protocol.TrafficSample{UserID: 7, AccountingPeriod: "paid", From: history.From, Through: history.Through, UploadBytes: 10}
	bad := native
	bad.AccountingPeriod = ""
	if err = store.AddAccountingWithHourly(Traffic{7: {10, 0}}, []protocol.TrafficSample{bad}, []protocol.HourlySample{history}); err == nil {
		t.Fatal("invalid native capture accepted")
	}
	if len(store.traffic.totals)+len(store.traffic.samples)+len(store.traffic.hourly) != 0 {
		t.Fatal("failed capture partially appended accounting")
	}
	if err = store.AddAccountingWithHourly(Traffic{7: {10, 0}}, []protocol.TrafficSample{native}, []protocol.HourlySample{history}); err != nil {
		t.Fatal(err)
	}
	batch, err := store.Batch()
	if err != nil || batch.Traffic[7][0] != 10 || len(batch.HourlySamples) != 1 || batch.HourlySamples[0].UploadBytes != 5 {
		t.Fatal("retry lost or duplicated one accounting bank", batch, err)
	}
}

func TestHourlyHistoryLossDoesNotDiscardNativeAccounting(t *testing.T) {
	for _, cause := range []string{"invalid", "overflow"} {
		t.Run(cause, func(t *testing.T) {
			store, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			history := hourlyHistoryFixture()
			if cause == "invalid" {
				history.CounterGeneration = 0
			} else {
				previous := history
				previous.UploadBytes = math.MaxInt64
				if err = store.AddAccountingWithHourly(nil, nil, []protocol.HourlySample{previous}); err != nil {
					t.Fatal(err)
				}
			}
			if err = store.AddAccountingWithHourly(Traffic{7: {10, 20}}, nil, []protocol.HourlySample{history}); err != nil {
				t.Fatal("presentation loss blocked native accounting", err)
			}
			batch, err := store.Batch()
			if err != nil || batch.Traffic[7] != [2]uint64{10, 20} || batch.DroppedHourlySamples != 1 || batch.DroppedSamples != 0 {
				t.Fatal("hourly loss changed native evidence", batch, err)
			}
		})
	}
}

func TestHourlyHistoryCopyAndQueueFootprintRemainImmutable(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	history := []protocol.HourlySample{hourlyHistoryFixture()}
	if err = store.AddAccountingWithHourly(nil, nil, history); err != nil {
		t.Fatal(err)
	}
	history[0].UploadBytes = 999
	batch, err := store.Batch()
	if err != nil || len(batch.HourlySamples) != 1 || batch.HourlySamples[0].UploadBytes != 5 {
		t.Fatal("caller changed accepted history", batch, err)
	}
	if store.traffic.queuedBytes != trafficFootprint(batch) {
		t.Fatal("hourly samples escaped the report memory budget")
	}
	batch.HourlySamples[0].Owner.ID = "foreign"
	batch.HourlySamples[0].UploadBytes = 999
	if replay := store.Pending(); replay.HourlySamples[0].Owner.ID != "account" || replay.HourlySamples[0].UploadBytes != 5 {
		t.Fatal("report consumer changed replay evidence", replay)
	}
	if advanced, err := store.Acknowledge(batch.ID); err != nil || !advanced || store.traffic.queuedBytes != 0 {
		t.Fatal("ACK retained or undercounted hourly allocations", err)
	}
}
