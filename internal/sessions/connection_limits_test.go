package sessions

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestClientReservationSurvivesPolicyChangesAndReleasesOnce(t *testing.T) {
	r, user := New(), testUser()
	user.ConnectionLimit, user.ActiveIPLimit = 1, 0
	r.SetUsers([]protocol.User{user})
	lease, err := r.AcquireTracked(context.Background(), user.ID, protocol.UserEmail(user, "in"), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := user.ID
	user.ID, user.ReplacesID = 123456, previous
	r.SetUsers([]protocol.User{user})
	r.SampleActivity()
	if _, err := acquire(r, user, "192.0.2.2", "udp"); err == nil {
		t.Fatal("replacement or idle sample lost live reservation")
	}
	if !r.Summary().Status[user.ID].Limited || r.Summary().Connections[user.ID] != 0 {
		t.Fatal("hard limit and sampled activity were conflated")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); lease.Close() }()
		go func() { defer wg.Done(); lease.Finish() }()
	}
	wg.Wait()
	if r.users[user.ID].clients != 0 || r.resources != 0 {
		t.Fatal("duplicate completion leaked or over-released a reservation")
	}
	fresh, err := acquire(r, user, "192.0.2.2", "udp")
	if err != nil {
		t.Fatal(err)
	}
	fresh.Close()
}

func TestTransitDoesNotConsumeOrReleaseMemberSlots(t *testing.T) {
	r, user := New(), testUser()
	user.ConnectionLimit, user.ActiveIPLimit = 1, 1
	binding := protocol.TransitCredential{SourceNodeID: "source-node", InboundTag: "in", Generation: "revision-1", Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440011"}`)}
	user.TransitCredentials = []protocol.TransitCredential{binding}
	r.SetUsers([]protocol.User{user})
	transit, err := r.Acquire(context.Background(), user.ID, protocol.TransitEmail(user.ID, binding), "in", "192.0.2.10", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	member, err := acquire(r, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal("transit consumed the member reservation", err)
	}
	transit.Close()
	r.SampleActivity()
	if _, err := acquire(r, user, "192.0.2.1", "udp"); err == nil {
		t.Fatal("transit close released the member reservation")
	}
	if r.Summary().TotalConnections[user.ID] != 1 || r.Summary().Connections[user.ID] != 0 {
		t.Fatal("idle member count changed telemetry meaning")
	}
	member.Close()
	fresh, err := acquire(r, user, "192.0.2.1", "udp")
	if err != nil {
		t.Fatal(err)
	}
	fresh.Close()
}

func TestLowerLimitPreservesFlowsAndFencesFurtherAdmission(t *testing.T) {
	r, user := New(), testUser()
	user.ConnectionLimit = 3
	r.SetUsers([]protocol.User{user})
	var leases []*Lease
	for i := 0; i < 3; i++ {
		lease, err := acquire(r, user, "192.0.2.1", "tcp")
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	defer r.CloseAll()
	user.ConnectionLimit = 1
	r.SetUsers([]protocol.User{user})
	if r.Summary().TotalConnections[user.ID] != 3 {
		t.Fatal("limit reduction revoked existing flows")
	}
	for _, lease := range leases {
		if _, err := acquire(r, user, "192.0.2.1", "udp"); err == nil {
			t.Fatal("lowered limit admitted another flow")
		}
		lease.Close()
	}
	fresh, err := acquire(r, user, "192.0.2.1", "udp")
	if err != nil {
		t.Fatal(err)
	}
	fresh.Close()
}
