package sessions

import (
	"context"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testUser() protocol.User {
	return protocol.User{ID: 1, UUID: "550e8400-e29b-41d4-a716-446655440000", InboundTags: []string{"in"}, ActiveIPLimit: 2, ConnectionLimit: 5}
}
func acquire(r *Registry, u protocol.User, ip, network string) (*Lease, error) {
	return r.Acquire(context.Background(), u.ID, protocol.UserEmail(u, "in"), "in", ip, "example.com:443", network, 443, nil)
}
func TestConcurrentAdmissionAndRelease(t *testing.T) {
	r := New()
	r.SetReportIPs(true)
	u := testUser()
	r.SetUsers([]protocol.User{u})
	var wg sync.WaitGroup
	var accepted atomic.Int64
	var leasesMu sync.Mutex
	var leases []*Lease
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, e := acquire(r, u, fmt.Sprintf("192.0.2.%d", i%10+1), []string{"tcp", "udp"}[i%2])
			if e == nil {
				accepted.Add(1)
				leasesMu.Lock()
				leases = append(leases, l)
				leasesMu.Unlock()
			}
			_ = r.Summary()
			_ = r.List("", 100)
		}(i)
	}
	wg.Wait()
	if accepted.Load() > 200 || len(r.users[1].ips) > 2 || r.Summary().Connections[1] != 0 {
		t.Fatal("admission exceeded limits")
	}
	for _, l := range leases {
		l.Close()
		l.Close()
	}
	if r.Summary().Connections[1] != 0 {
		t.Fatal("slots leaked")
	}
}
func TestCredentialGenerationAndRevocation(t *testing.T) {
	r := New()
	u := testUser()
	r.SetUsers([]protocol.User{u})
	l, e := acquire(r, u, "192.0.2.1", "tcp")
	if e != nil {
		t.Fatal(e)
	}
	next := u
	next.UUID = "550e8400-e29b-41d4-a716-446655440001"
	r.SetUsers([]protocol.User{next})
	if len(r.List("", 100)) != 0 {
		t.Fatal("rotated session remained")
	}
	if _, e = acquire(r, u, "192.0.2.1", "tcp"); e == nil {
		t.Fatal("old mux identity readmitted")
	}
	l.Close()
	fresh, e := acquire(r, next, "192.0.2.1", "udp")
	if e != nil {
		t.Fatal(e)
	}
	r.SetUsers([]protocol.User{})
	fresh.Close()
	if _, e = acquire(r, next, "192.0.2.1", "udp"); e == nil {
		t.Fatal("removed user readmitted")
	}
}
func TestControlsPortsAndBans(t *testing.T) {
	r := New()
	u := testUser()
	r.SetUsers([]protocol.User{u})
	l, e := acquire(r, u, "::ffff:192.0.2.1", "udp")
	if e != nil {
		t.Fatal(e)
	}
	l.Account(true, 1)
	r.SampleActivity()
	u.BlockNew = true
	r.SetUsers([]protocol.User{u})
	if r.Summary().Connections[1] != 1 {
		t.Fatal("block_new terminated established session")
	}
	if _, e = acquire(r, u, "192.0.2.1", "tcp"); e == nil {
		t.Fatal("block_new ignored")
	}
	r.SetPorts([]protocol.PortRange{{From: 443, To: 443, Network: "udp"}})
	if r.Summary().Connections[1] != 0 {
		t.Fatal("domain destination not closed")
	}
	l.Close()
	u.BlockNew = false
	r.SetUsers([]protocol.User{u})
	r.Ban(1, time.Now().Add(time.Second))
	if _, e = acquire(r, u, "192.0.2.1", "tcp"); e == nil {
		t.Fatal("ban ignored")
	}
	r.ExpireBans(time.Now().Add(2 * time.Second))
	l, e = acquire(r, u, "192.0.2.1", "tcp")
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
}
