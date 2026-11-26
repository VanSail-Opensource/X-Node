package sessions

import (
	"context"
	"errors"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestExplicitIdentityRevocationFencesNativeTransport(t *testing.T) {
	for _, mode := range []string{"set", "publish"} {
		t.Run(mode, func(t *testing.T) {
			r, user := New(), testUser()
			user.ConnectionLimit, user.ActiveIPLimit = 0, 0
			user.WhitelistEnabled = true
			user.WhitelistedIPs = []string{"192.0.2.1", "192.0.2.2"}
			var revision uint64
			publish := func(users ...protocol.User) {
				if mode == "set" {
					r.SetUsers(users)
				} else {
					revision++
					if !r.ApplyAuthorization(state.AuthorizationView{Sequence: revision, Revision: revision, Users: users}) {
						t.Fatal("authorization publication rejected")
					}
				}
			}
			publish(user)
			acquire := func(ip string, fences *int) *Lease {
				t.Helper()
				lease, err := r.AcquireTrackedWithTransportFence(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", ip, "example.com:443", "tcp", 443, nil, func() {
					_ = r.Summary() // The native fence must run outside r.mu.
					(*fences)++
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { lease.Close(); lease.Finish() })
				return lease
			}
			var retainedFences, removedFences, completedFences int
			retained := acquire("192.0.2.1", &retainedFences)
			removed := acquire("192.0.2.2", &removedFences)
			completed := acquire("192.0.2.1", &completedFences)
			completed.Close()
			completed.Finish()

			user.WhitelistedIPs = []string{"192.0.2.1"}
			publish(user)
			if retained.closed || !removed.closed || removedFences != 0 || completedFences != 0 {
				t.Fatal("source-only revocation or normal completion fenced a native transport")
			}

			publish()
			publish()
			if !retained.closed || retainedFences != 1 || removedFences != 0 || completedFences != 0 {
				t.Fatalf("explicit revocation must fence only the active invalidated transport once: %d/%d/%d", retainedFences, removedFences, completedFences)
			}
		})
	}
}

func TestUnlimitedSpeedPolicyStopsCancelledTransfers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	policy := newSpeedPolicy(protocol.User{})
	if err := policy.wait(ctx, 128); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := policy.wait(ctx, 128); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled unlimited transfer returned %v", err)
	}
}
