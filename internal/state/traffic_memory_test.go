package state

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestTrafficNeverPersistsThroughFailuresOrDurableChanges(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddTraffic(Traffic{7: {10, 20}}); err != nil {
		t.Fatal(err)
	}
	batch, err := s.Batch()
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.ValidStreamID(batch.StreamID) || batch.StreamID != s.StreamID() {
		t.Fatal("traffic is not bound to this boot")
	}
	after, _ := os.ReadFile(s.path)
	if !bytes.Equal(before, after) {
		t.Fatal("traffic capture/report wrote persistent state")
	}
	user := protocol.User{ID: 7, UUID: "durable-credential", AccountingPeriod: "paid", InboundTags: []string{"in"}}
	if err := s.Authorize([]protocol.User{user}, 1); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(s.path)
	if bytes.Contains(after, []byte(batch.ID)) || bytes.Contains(after, []byte(batch.StreamID)) {
		t.Fatal("durable configuration spilled volatile traffic")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := reopened.Batch(); err != nil || pending != nil || reopened.StreamID() == s.StreamID() {
		t.Fatal("restart restored uncommitted traffic or reused the boot stream", err)
	}
	if got := reopened.Snapshot(); got.Revision != 1 || len(got.Users) != 1 || got.Users[0].UUID != user.UUID {
		t.Fatal("traffic loss affected durable authorization")
	}
	s.path = filepath.Join(s.path, "unwritable", "state.json")
	if err := s.AddTraffic(Traffic{7: {3, 4}}); err != nil {
		t.Fatal("disconnected accumulation depended on disk", err)
	}
	if _, err := s.Flush(); err != nil {
		t.Fatal("volatile barrier depended on disk", err)
	}
	if advanced, err := s.Acknowledge(batch.ID); err != nil || !advanced {
		t.Fatal("volatile ACK depended on disk", err)
	}
}

func TestTrafficCapacityRecordsLossWithoutBlockingDurableState(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	for i := range MaxTrafficEntries + 100 {
		sample := protocol.TrafficSample{UserID: 1, AccountingPeriod: "paid", From: at.Add(time.Duration(i) * time.Minute), Through: at.Add(time.Duration(i)*time.Minute + time.Second), UploadBytes: 1}
		if err := s.AddAccounting(Traffic{1: {1, 0}}, []protocol.TrafficSample{sample}); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.traffic.samples)+len(s.traffic.totals) > MaxTrafficEntries || s.traffic.dropped == 0 {
		t.Fatal("accumulation is unbounded or loss was hidden")
	}
	batch, err := s.Batch()
	if err != nil || batch.DroppedSamples == 0 || batch.Traffic[1][0]+batch.DroppedSamples != MaxTrafficEntries+100 {
		t.Fatal("loss marker fabricated or hid traffic", err)
	}
	for range MaxTrafficQueuedReports - 1 {
		if err := s.AddTraffic(Traffic{1: {1, 0}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddTraffic(Traffic{1: {1, 0}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Flush(); err != ErrTrafficBusy {
		t.Fatal("queue pressure did not return a retryable barrier", err)
	}
	if s.traffic.queuedBytes > MaxTrafficQueuedBytes || len(s.traffic.queue) > MaxTrafficQueuedReports {
		t.Fatal("pending report memory exceeded bounds")
	}
	if err := s.Ban(7, at.Add(time.Hour)); err != nil {
		t.Fatal("traffic pressure prevented a durable ban", err)
	}
	if err := s.Ack(batch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Flush(); err != nil {
		t.Fatal("barrier did not recover after acknowledgement", err)
	}
}

func BenchmarkTrafficMemoryAccumulation(b *testing.B) {
	s, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	var samples []protocol.TrafficSample
	delta := Traffic{}
	for i := 1; i <= 1000; i++ {
		delta[i] = [2]uint64{1, 2}
		samples = append(samples, protocol.TrafficSample{UserID: i, AccountingPeriod: fmt.Sprint("paid-", i), From: at, Through: at.Add(time.Second), UploadBytes: 1, DownloadBytes: 2})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := s.AddAccounting(delta, samples); err != nil {
			b.Fatal(err)
		}
	}
}
