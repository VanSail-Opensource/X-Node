package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSerializedReceiptAndAggregateBounds(t *testing.T) {
	var history []JobResult
	for i := 0; i < 200; i++ {
		result := boundedJobResult(JobResult{ID: fmt.Sprint(i), Command: "update.rollback", Status: "completed", Data: strings.Repeat("x", 48<<10)})
		var err error
		history, err = retainJob(history, result, true)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := marshalJobBounded(history, maxJobJournalBytes-1)
		if err != nil || len(raw) >= maxJobJournalBytes || len(history) > maxJobHistory {
			t.Fatal("aggregate byte or receipt bound failed")
		}
	}
	oversized := boundedJobResult(JobResult{ID: "large", Command: "update.rollback", Status: "completed", Data: strings.Repeat("x", maxJobResultBytes)})
	if oversized.Status != "uncertain" || oversized.Data != nil {
		t.Fatal("truncated mutation was exposed as completed")
	}
}

func TestUncertainReceiptsCannotBeEvictedForAnotherMutation(t *testing.T) {
	results := make(chan protocol.Message, 2)
	jobs, err := NewJobs(t.TempDir(), journalSink(results))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxJobHistory; i++ {
		jobs.history, err = retainJob(jobs.history, boundedJobResult(JobResult{ID: fmt.Sprint(i), Command: "update.rollback", Status: "uncertain"}), true)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := jobs.Start(context.Background(), "overflow", "update.rollback", func(context.Context, func(any)) (any, error) {
		t.Error("capacity failure executed mutation")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	result := journalResult(t, results)
	if result.Status != "failed" || !strings.Contains(result.Error, "capacity") || len(jobs.history) != maxJobHistory {
		t.Fatal("uncertain identities were evicted")
	}
}

func TestLargeReadResultsCannotEnlargeDiskOrRetainedHistory(t *testing.T) {
	results := make(chan protocol.Message, 256)
	jobs, err := NewJobs(t.TempDir(), journalSink(results))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		id := fmt.Sprint(i)
		if err := jobs.Start(context.Background(), id, "firewall.status", func(context.Context, func(any)) (any, error) { return strings.Repeat("x", 48<<10), nil }); err != nil {
			t.Fatal(err)
		}
		if result := journalResult(t, results); result.Status != "completed" {
			t.Fatal("bounded read failed")
		}
		deadline := time.Now().Add(3 * time.Second)
		for len(jobs.slots) != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if len(jobs.slots) != 0 {
			t.Fatal("completed executor slot did not drain")
		}
	}
	if _, err := os.Stat(jobs.path); !os.IsNotExist(err) {
		t.Fatal("read-only policy snapshots wrote a journal")
	}
	raw, err := json.Marshal(jobs.Snapshot())
	if err != nil || len(raw) >= maxJobJournalBytes || len(jobs.Snapshot()) > maxJobHistory {
		t.Fatal("volatile history exceeded its byte bound")
	}
}

func TestLargeObservationReturnsWithinWireLimitWithoutRetention(t *testing.T) {
	results := make(chan protocol.Message, 1)
	jobs, err := NewJobs(t.TempDir(), journalSink(results))
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Start(context.Background(), "large-policy", "firewall.status", func(context.Context, func(any)) (any, error) { return strings.Repeat("x", 128<<10), nil }); err != nil {
		t.Fatal(err)
	}
	result := journalResult(t, results)
	if result.Status != "completed" || len(result.Data.(string)) != 128<<10 {
		t.Fatal("large valid observation was truncated on the wire")
	}
	if len(jobs.Snapshot()) != 0 {
		t.Fatal("large read payload was retained")
	}
}
