package sessions

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
	"time"
)

func TestOldPeriodBarrierDoesNotCloseRenewedStreams(t *testing.T) {
	registry, user := New(), testUser()
	user.AccountingPeriod = "old-period"
	registry.SetUsers([]protocol.User{user})
	old, err := registry.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	user.AccountingPeriod = "new-period"
	registry.SetUsers([]protocol.User{user})
	current, err := registry.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	defer current.Finish()
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		release, err := registry.QuiescePeriod(ctx, user.ID, "old-period")
		if release != nil {
			defer release()
		}
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("old handler completion was not awaited")
	case <-time.After(10 * time.Millisecond):
	}
	old.Account(false, 19)
	old.Finish()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	current.Account(true, 1)
	registry.SampleActivity()
	if registry.Summary().Connections[user.ID] != 1 {
		t.Fatal("new term was interrupted")
	}
	if _, err = registry.QuiescePeriod(ctx, user.ID, "new-period"); err == nil {
		t.Fatal("active accounting period was sealed")
	}
	counters := registry.AccountingCounters()
	found := false
	for _, counter := range counters {
		if counter.Period == "old-period" && counter.Download == 19 {
			found = true
		}
	}
	if !found {
		t.Fatal("late bytes lost their old period")
	}
}
