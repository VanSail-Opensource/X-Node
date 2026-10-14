package state

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAccountingBarrierPreservesPendingAndPeriodReplay(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	add := func(period string, bytes uint64) {
		t.Helper()
		err := store.AddAccounting(Traffic{7: {bytes, 0}}, []protocol.TrafficSample{{UserID: 7, AccountingPeriod: period, From: at, Through: at.Add(time.Second), UploadBytes: bytes}})
		if err != nil {
			t.Fatal(err)
		}
	}
	add("old-period", 10)
	first, err := store.Batch()
	if err != nil {
		t.Fatal(err)
	}
	add("old-period", 2)
	add("new-period", 3)
	barrier, err := store.Flush()
	if err != nil || barrier.Sequence != 2 {
		t.Fatalf("barrier=%+v,error=%v", barrier, err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopened.Batch()
	if err != nil || pending.ID != first.ID || pending.Traffic[7][0] != 10 || pending.Samples[0].AccountingPeriod != "old-period" {
		t.Fatalf("old immutable batch changed: %+v,%v", pending, err)
	}
	if err = reopened.Ack("wrong-batch"); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Ack(first.ID); err != nil {
		t.Fatal(err)
	}
	next, err := reopened.Batch()
	if err != nil || next.ID == first.ID || len(next.Samples) != 2 || next.Traffic[7][0] != 5 {
		t.Fatalf("queued periods lost: %+v,%v", next, err)
	}
	periods := map[string]uint64{}
	for _, sample := range next.Samples {
		periods[sample.AccountingPeriod] += sample.UploadBytes
	}
	if periods["old-period"] != 2 || periods["new-period"] != 3 {
		t.Fatalf("period attribution=%v", periods)
	}
}

func TestAccountingOverflowLeavesAllCountersUnchanged(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	sample := protocol.TrafficSample{UserID: 1, AccountingPeriod: "period", From: at, Through: at, UploadBytes: ^uint64(0)}
	if err = store.AddAccounting(Traffic{1: {^uint64(0), 0}}, []protocol.TrafficSample{sample}); err != nil {
		t.Fatal(err)
	}
	sample.UploadBytes = 1
	if err = store.AddAccounting(Traffic{1: {1, 0}}, []protocol.TrafficSample{sample}); err == nil {
		t.Fatal("overflow accepted")
	}
	batch, err := store.Batch()
	if err != nil || batch.Traffic[1][0] != ^uint64(0) || batch.Samples[0].UploadBytes != ^uint64(0) {
		t.Fatal("failed mutation changed durable counters")
	}
}
