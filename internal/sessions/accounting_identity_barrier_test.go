package sessions

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAccountingBarrierRetainsOriginalPrincipalAfterIdentityReplacement(t *testing.T) {
	for _, test := range []struct {
		name         string
		periodScoped bool
		current      bool
	}{
		{name: "original-principal"},
		{name: "original-period", periodScoped: true},
		{name: "current-principal", current: true},
		{name: "current-period", periodScoped: true, current: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry, before := New(), identityIPUser(1, testUser().UUID)
			registry.SetUsers([]protocol.User{before})
			open := func(user protocol.User) *Lease {
				t.Helper()
				lease, err := registry.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(lease.Finish)
				t.Cleanup(lease.Close)
				return lease
			}
			old := open(before)
			old.Account(true, 10)
			after := before
			after.ID, after.ReplacesID = 100, before.ID
			registry.SetUsers([]protocol.User{after})
			current := open(after)
			subject := before.ID
			if test.current {
				subject = after.ID
				after.BlockNew = true
				registry.SetUsers([]protocol.User{after})
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var release func()
				var err error
				if test.periodScoped {
					release, err = registry.QuiescePeriod(ctx, subject, before.AccountingPeriod)
				} else {
					release, err = registry.Quiesce(ctx, subject)
				}
				if release != nil {
					defer release()
				}
				done <- err
			}()
			select {
			case err := <-done:
				t.Fatalf("barrier forgot the original principal's unfinished accounting: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			old.Account(false, 19)
			old.Finish()
			if test.current {
				select {
				case err := <-done:
					t.Fatalf("current-principal barrier forgot the replacement handler: %v", err)
				case <-time.After(20 * time.Millisecond):
				}
				current.Finish()
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			registry.mu.RLock()
			oldClosed, currentClosed := old.closed, current.closed
			registry.mu.RUnlock()
			if !oldClosed || currentClosed != test.current {
				t.Fatal("barrier closed the wrong original/replacement accounting handlers")
			}
			if !test.current {
				current.Account(true, 3)
			}
			var retained AccountingCounter
			for _, counter := range registry.AccountingCounters() {
				if counter.UserID == before.ID {
					retained = counter
				}
			}
			if retained.Period != before.AccountingPeriod || retained.Upload != 10 || retained.Download != 19 {
				t.Fatal("barrier did not capture late bytes against their original principal", retained)
			}
		})
	}
}
