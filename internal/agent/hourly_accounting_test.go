package agent

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestHourlyStorageFailureReconnectStillAcknowledgesWholeHistoricalReport(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	first := f.peer(t)
	f.config.Users[0].Hourly = nil
	f.apply(t, first)
	f.ackTraffic.Store(false)
	now := time.Now().UTC()
	sample := protocol.HourlySample{Owner: protocol.HourlyOwner{ID: "account", Generation: 7}, EnrollmentID: "old-enrollment", UserID: 1, AccountingPeriod: "hourly-period", DayUTC: now.Format(time.DateOnly), CounterGeneration: 1, From: now, Through: now, UploadBytes: 3, DownloadBytes: 4}
	if err := f.a.Store.AddAccountingWithHourly(state.Traffic{1: {3, 4}}, nil, []protocol.HourlySample{sample}); err != nil {
		t.Fatal(err)
	}
	batch, err := f.a.Store.Batch()
	if err != nil || batch == nil || len(batch.HourlySamples) != 1 {
		t.Fatal("historical mixed report fixture was not sealed", err)
	}
	original, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	f.a.requestReports(reportReplay)
	if frame := f.frame(t, first, "traffic.report", batch.ID); !bytes.Equal(frame.Data, original) {
		t.Fatal("first transmission rewrote historical accounting")
	}
	if err = f.a.hourly.store.Close(); err != nil {
		t.Fatal(err)
	}
	if f.a.checkHourlyHealth() {
		t.Fatal("constructed storage failure did not disable admission")
	}
	second := f.peer(t)
	await(t, func() bool { return f.a.Client.Connected() && f.a.Client.HourlyAccounting() && !f.a.Client.Hourly() })
	if second.session != "" || !f.a.Runtime.Ready() {
		t.Fatal("receipt-only reconnect restored hourly admission or stopped legacy runtime")
	}
	f.ackTraffic.Store(true)
	f.a.requestReports(reportReplay)
	frame := f.frame(t, second, "traffic.report", batch.ID)
	if !bytes.Equal(frame.Data, original) {
		t.Fatal("storage failure stripped or relabeled the mixed immutable report")
	}
	await(t, func() bool {
		pending := f.a.Store.Pending()
		return pending == nil || pending.ID != batch.ID
	})
	if f.a.Client.Hourly() || f.a.checkHourlyHealth() {
		t.Fatal("historical traffic receipt restored unhealthy hourly access")
	}
}
