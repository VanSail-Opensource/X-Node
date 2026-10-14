package agent

import (
	"context"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestCaptureKeepsLateClosedStreamBytesInOriginalPeriod(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry := sessions.New()
	user := protocol.User{ID: 1, UUID: "550e8400-e29b-41d4-a716-446655440000", InboundTags: []string{"in"}, AccountingPeriod: "old"}
	registry.SetUsers([]protocol.User{user})
	acquire := func() *sessions.Lease {
		t.Helper()
		lease, err := registry.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
		if err != nil {
			t.Fatal(err)
		}
		return lease
	}
	old := acquire()
	process := &Agent{Store: store, Registry: registry, previous: state.Traffic{}, previousAccounting: map[string][2]uint64{}}
	old.Account(true, 10)
	if err = process.captureTraffic(); err != nil {
		t.Fatal(err)
	}
	user.AccountingPeriod = "new"
	registry.SetUsers([]protocol.User{user})
	current := acquire()
	old.Account(false, 7)
	old.Finish()
	current.Account(true, 3)
	if err = process.captureTraffic(); err != nil {
		t.Fatal(err)
	}
	batch, err := store.Batch()
	if err != nil || len(batch.Samples) != 2 {
		t.Fatalf("samples=%+v,error=%v", batch, err)
	}
	periods := map[string][2]uint64{}
	for _, sample := range batch.Samples {
		periods[sample.AccountingPeriod] = [2]uint64{sample.UploadBytes, sample.DownloadBytes}
	}
	if periods["old"] != [2]uint64{10, 7} || periods["new"] != [2]uint64{3, 0} {
		t.Fatalf("mixed accounting periods: %v", periods)
	}
	current.Close()
	current.Finish()
}
