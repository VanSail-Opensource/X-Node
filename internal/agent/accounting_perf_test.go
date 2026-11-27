package agent

import (
	"fmt"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func BenchmarkCaptureNativeAccounting(b *testing.B) {
	for _, mode := range []string{"unused", "settled", "busy"} {
		b.Run(mode, func(b *testing.B) {
			store, err := state.Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			registry := sessions.New()
			users := make([]protocol.User, 1000)
			for i := range users {
				users[i] = protocol.User{ID: i + 1, UUID: fmt.Sprintf("550e8400-e29b-41d4-a716-%012x", i), InboundTags: []string{"in"}, AccountingPeriod: fmt.Sprintf("billing-period-%d", i)}
			}
			registry.SetUsers(users)
			leases := make([]*sessions.Lease, 0, len(users))
			for _, user := range users {
				lease, err := registry.Acquire(b.Context(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
				if err != nil {
					b.Fatal(err)
				}
				if mode != "unused" {
					lease.Account(true, 128)
				}
				leases = append(leases, lease)
			}
			defer registry.CloseAll()
			a := &Agent{Store: store, Registry: registry}
			if err := a.captureTraffic(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if mode == "busy" {
					// Accumulate real deltas through the registry, without
					// involving a socket or varying the active lease set.
					for _, lease := range leases {
						lease.Account(true, 128)
					}
				}
				if err := a.captureTraffic(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
