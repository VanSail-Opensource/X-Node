package agent

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestFlushCaptureDoesNotConsumeThroughputOrActivitySamples(t *testing.T) {
	// Filesystem setup happens outside the fake-time bubble.
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		registry := sessions.New()
		user := protocol.User{ID: 1, UUID: "550e8400-e29b-41d4-a716-446655440000", InboundTags: []string{"in"}, AccountingPeriod: "paid"}
		registry.SetUsers([]protocol.User{user})
		lease, err := registry.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { lease.Close(); lease.Finish() }()
		a := &Agent{Store: store, Registry: registry}
		lease.Account(true, 10)
		if err := a.sampleTraffic(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		lease.Account(true, 5)
		if err := a.captureTraffic(); err != nil {
			t.Fatal(err)
		}
		if rate := registry.Summary().Rates[1]; rate.UploadBytesPerSecond != 10 {
			t.Fatal("manual capture changed sampled rate", rate)
		}
		time.Sleep(time.Second)
		lease.Account(true, 5)
		if err := a.sampleTraffic(); err != nil {
			t.Fatal(err)
		}
		snapshot := registry.Summary()
		if rate := snapshot.Rates[1]; rate.UploadBytesPerSecond != 5 || rate.SampleSeconds != 2 {
			t.Fatal("flush consumed bytes from the next sample", rate)
		}
		if snapshot.Connections[1] != 1 || len(snapshot.ActiveIPs[1]) != 1 {
			t.Fatal("mandatory activity/count sample missing", snapshot)
		}
	})
}
