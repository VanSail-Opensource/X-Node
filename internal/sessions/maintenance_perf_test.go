package sessions

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestExpirySkipsIdleAndClosesOnlyExpiredOrdinaryFlows(t *testing.T) {
	r := New()
	base := time.Now()
	soon, later := base.Add(time.Hour), base.Add(2*time.Hour)
	makeUser := func(id int, until *time.Time) protocol.User {
		return protocol.User{ID: id, UUID: "d9428888-122b-11e1-b85c-61cd3cbb3210", InboundTags: []string{"in"}, ValidUntil: until}
	}
	users := []protocol.User{makeUser(1, &soon), makeUser(2, &later), makeUser(3, &soon), makeUser(4, &soon)}
	r.SetUsers(users)
	for _, i := range []int{0, 1, 3} {
		u := users[i]
		lease, err := r.Acquire(context.Background(), u.ID, protocol.UserEmail(u, "in"), "in", "192.0.2.1", "example.com", "tcp", 443, func() { _ = r.Summary() })
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
	}
	r.ExpireUsers(soon)
	r.ExpireUsers(soon)
	got := r.Summary().TotalConnections
	if len(got) != 1 || got[2] != 1 {
		t.Fatalf("expiry left connections %v, want only the unexpired user", got)
	}
}

func BenchmarkRegistryExpiryWithIdleExpiredUsers(b *testing.B) {
	r := New()
	now := time.Now()
	for id := 1; id <= 2000; id++ {
		u := &userState{}
		r.users[id] = u
		if id <= 1000 {
			u.policy.ValidUntil = &now
			continue
		}
		for range 4 {
			connID := strconv.Itoa(len(r.connections))
			r.connections[connID] = &Lease{Info: Connection{UserID: id}, user: u}
			u.count++
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		r.ExpireUsers(now)
	}
}

func BenchmarkRegistrySummary(b *testing.B) {
	r := New()
	r.rates = map[int]protocol.UserRate{}
	now := time.Now()
	for id := 1; id <= 2000; id++ {
		r.users[id] = &userState{}
		r.rates[id] = protocol.UserRate{SampleSeconds: 1, UploadBytesPerSecond: 1000}
		for ip := 1; ip <= 5; ip++ {
			r.activityHistory.observe(activityIP{id, "192.0.2." + strconv.Itoa(ip)}, now)
		}
	}
	r.activityHistory.sampled = now
	b.ReportAllocs()
	for b.Loop() {
		_ = r.Summary()
	}
}

func BenchmarkRegistryPayloadSpeedLookup(b *testing.B) {
	r := New()
	u := protocol.User{ID: 1, UUID: "d9428888-122b-11e1-b85c-61cd3cbb3210", InboundTags: []string{"in"}}
	r.SetUsers([]protocol.User{u})
	ctx := context.Background()
	lease, err := r.Acquire(ctx, u.ID, protocol.UserEmail(u, "in"), "in", "192.0.2.1", "example.com", "tcp", 443, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer lease.Close()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = lease.Wait(ctx, 2048)
		}
	})
}
