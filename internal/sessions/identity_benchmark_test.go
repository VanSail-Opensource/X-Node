package sessions

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func BenchmarkIdentityLookup(b *testing.B) {
	user := testUser()
	for i := range 8 {
		user.TransitCredentials = append(user.TransitCredentials, protocol.TransitCredential{
			SourceNodeID: fmt.Sprintf("node-%d", i), InboundTag: "in", Generation: "route-1",
			Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440011"}`),
		})
	}
	registry := New()
	index := registry.identities(user)
	identity := protocol.UserEmail(user, "in")
	b.Run("derived", func(b *testing.B) {
		for range b.N {
			for _, binding := range user.TransitCredentials {
				_ = protocol.TransitEmail(user.ID, binding) == identity
			}
			if protocol.UserEmail(user, "in") != identity {
				b.Fatal("identity differs")
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		for range b.N {
			if transit, valid := index.lookup(identity, "in"); !valid || transit {
				b.Fatal("identity differs")
			}
		}
	})
}
