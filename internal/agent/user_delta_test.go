package agent

import (
	"context"
	"fmt"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestUserDeltaPreservesOrderAndRejectsAmbiguousRevocation(t *testing.T) {
	a, config := activationFixture(t)
	defer a.Certificates.Stop()
	for id := 2; id <= 20; id++ {
		user := config.Users[0]
		user.ID, user.UUID = id, fmt.Sprintf("550e8400-e29b-41d4-a716-%012d", id)
		config.Users = append(config.Users, user)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.handle(ctx, protocol.New("state.sync", "baseline", 1, config))
	before := a.Store.Snapshot()
	if before.Revision != 1 {
		t.Fatal("fixture authorization was not accepted")
	}
	// A formerly accepted DDNS entry can become invalid under newer ingress
	// checks. It must fail only its utility and never block later user changes.
	a.desired.DDNS = []protocol.DDNSJob{{ID: "old-failed-ddns", Provider: protocol.BuiltinDDNSProvider}}
	if a.desired.Validate() == nil {
		t.Fatal("fixture did not retain an invalid old utility setting")
	}
	bad := protocol.New("users.delta", "ambiguous", 2, protocol.UsersDelta{Upsert: config.Users[:1], Remove: []int{1}})
	bad.BaseRevision = 1
	a.handle(ctx, bad)
	if a.Store.Revision() != 1 {
		t.Fatal("contradictory remove and upsert changed authorization")
	}
	for revision := uint64(2); revision <= 12; revision++ {
		user := config.Users[10]
		user.ConnectionLimit = int(revision)
		delta := protocol.New("users.delta", "limits", revision, protocol.UsersDelta{Upsert: []protocol.User{user}})
		delta.BaseRevision = revision - 1
		a.handle(ctx, delta)
		current := a.Store.Snapshot()
		if current.Revision != revision {
			t.Fatal("valid authorization delta was not accepted")
		}
		for index, original := range config.Users {
			if current.Users[index].ID != original.ID || a.desired.Users[index].ID != original.ID {
				t.Fatal("delta reordered unchanged native identities")
			}
		}
		if protocol.Classify(config, a.desired).Native {
			t.Fatal("limit-only delta requested native reconstruction")
		}
	}
}
