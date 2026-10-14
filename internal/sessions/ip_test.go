package sessions

import (
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
	"time"
)

func TestIPReportingOptInAndScopedBlock(t *testing.T) {
	r := New()
	u := testUser()
	r.SetUsers([]protocol.User{u})
	l, e := acquire(r, u, "::ffff:192.0.2.1", "tcp")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if r.Summary().ActiveIPs != nil {
		t.Fatal("IP leaked without request")
	}
	ips := r.ActiveIPs(1)
	if len(ips) != 1 || ips[0].UserID != 1 || ips[0].SourceIP != "192.0.2.1" {
		t.Fatal("requested IP/user report incomplete")
	}
	r.SetReportIPs(true)
	if len(r.Summary().ActiveIPs[1]) != 1 {
		t.Fatal("opted-in report missing IP")
	}
	var event AdmissionEvent
	r.OnReject = func(e AdmissionEvent) { event = e }
	block := protocol.IPBlock{SourceIP: "192.0.2.1", UserID: 1, Until: time.Now().Add(time.Minute)}
	r.SetIPBlock(IPBlockKey(1, block.SourceIP), block)
	if _, e = acquire(r, u, "192.0.2.1", "udp"); e == nil {
		t.Fatal("source IP block ignored")
	}
	if !event.Limited || event.Reason != "ip_temp_block" || event.UserID != 1 {
		t.Fatal("rejection reason missing")
	}
	if r.Summary().Connections[1] != 1 {
		t.Fatal("block-only closed established session")
	}
	if r.DropIP(block.SourceIP, 1) != 1 || r.Summary().Connections[1] != 0 {
		t.Fatal("IP drop did not close session")
	}
	r.ExpireIPBlocks(time.Now().Add(2 * time.Minute))
	fresh, e := acquire(r, u, block.SourceIP, "udp")
	if e != nil {
		t.Fatal(e)
	}
	fresh.Close()
}
func TestLimitedStatusReasonAndScope(t *testing.T) {
	r := New()
	u := testUser()
	u.ActiveIPLimit = 1
	r.SetUsers([]protocol.User{u})
	l, e := acquire(r, u, "192.0.2.1", "tcp")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	status := r.Summary().Status[1]
	if !status.Limited || status.Reason != "active_ip_limit" || status.Scope != "new_ip" {
		t.Fatal("IP threshold status wrong")
	}
	u.BlockNew = true
	r.SetUsers([]protocol.User{u})
	status = r.Summary().Status[1]
	if !status.Limited || status.Reason != "block_new" || status.Scope != "new_connection" {
		t.Fatal("block_new status missing")
	}
}
