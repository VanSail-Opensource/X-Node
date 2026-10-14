package sessions

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestQuiescenceWaitsForNativeCompletionAndKeepsOldPeriod(t *testing.T) {
	registry, user := New(), testUser()
	user.AccountingPeriod = "old-period"
	registry.SetUsers([]protocol.User{user})
	lease, err := registry.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	user.BlockNew = true
	registry.SetUsers([]protocol.User{user})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		release, err := registry.Quiesce(ctx, user.ID)
		if release != nil {
			defer release()
		}
		done <- err
	}()
	lease.Close()
	registry.PruneCounters()
	select {
	case err := <-done:
		t.Fatalf("barrier ignored unfinished handler: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	user.AccountingPeriod = "new-period"
	registry.SetUsers([]protocol.User{user})
	lease.Account(false, 17)
	lease.Finish()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	counters := registry.AccountingCounters()
	if len(counters) != 1 || counters[0].Period != "old-period" || counters[0].Download != 17 {
		t.Fatalf("late bytes moved periods: %+v", counters)
	}
}

func TestExpiredAuthorizationDeniesAdmissionAndClosesExistingStreams(t *testing.T) {
	registry, user := New(), testUser()
	until := time.Now().Add(time.Minute)
	user.ValidUntil = &until
	registry.SetUsers([]protocol.User{user})
	lease, err := acquire(registry, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(-time.Second)
	registry.SetUsers([]protocol.User{user})
	registry.ExpireUsers(time.Now())
	if _, err = acquire(registry, user, "192.0.2.1", "tcp"); err == nil {
		t.Fatal("expired admission accepted")
	}
	if registry.Summary().Connections[user.ID] != 0 || registry.Summary().Status[user.ID].Reason != "expired" {
		t.Fatal("expiry left active access")
	}
	lease.Close()
}

func TestMeasuredRatesAreSeparateFromSpeedCaps(t *testing.T) {
	registry, user := New(), testUser()
	user.AccountingPeriod, user.SpeedLimitMbps = "period", 100
	registry.SetUsers([]protocol.User{user})
	registry.SetRates(protocol.Traffic{user.ID: {2000, 6000}}, 2)
	summary := registry.Summary()
	if summary.Rates[user.ID].UploadBytesPerSecond != 1000 || summary.Rates[user.ID].DownloadBytesPerSecond != 3000 || summary.Speed[user.ID].NormalMbps != 100 {
		t.Fatal("rates or cap units were confused")
	}
}
