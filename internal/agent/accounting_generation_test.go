package agent

import (
	"context"
	"fmt"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestCaptureRestoredPeriodUsesFreshCounterGeneration(t *testing.T) {
	for _, fresh := range []uint64{1, 10, 25} {
		t.Run(fmt.Sprint(fresh), func(t *testing.T) {
			store, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			registry := sessions.New()
			user := protocol.User{ID: 1, UUID: "550e8400-e29b-41d4-a716-446655440000", InboundTags: []string{"in"}, AccountingPeriod: "paid"}
			registry.SetUsers([]protocol.User{user})
			acquire := func() *sessions.Lease {
				t.Helper()
				lease, err := registry.Acquire(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
				if err != nil {
					t.Fatal(err)
				}
				return lease
			}
			process := &Agent{Store: store, Registry: registry, previous: state.Traffic{}, previousAccounting: map[string][2]uint64{}}
			capture := func() {
				t.Helper()
				if err := process.captureTraffic(); err != nil {
					t.Fatal(err)
				}
			}
			old := acquire()
			old.Account(true, 10)
			capture()
			old.Close()
			registry.SetUsers(nil)
			capture()
			registry.SetUsers([]protocol.User{user})
			current := acquire()
			defer current.Close()
			current.Account(true, fresh)
			capture()
			capture()
			batch, err := store.Batch()
			if err != nil {
				t.Fatal(err)
			}
			if batch == nil || len(batch.Samples) != 1 || batch.Samples[0].UploadBytes != 10+fresh || batch.Traffic[user.ID][0] != 10+fresh {
				t.Fatalf("restored period lost or replayed bytes: %+v", batch)
			}
		})
	}
}
