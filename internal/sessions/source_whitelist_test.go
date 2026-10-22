package sessions

import (
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSourceWhitelistAdmissionAndExistingSessionRevocation(t *testing.T) {
	r := New()
	user := testUser()
	user.WhitelistEnabled = true
	user.WhitelistedIPs = []string{"192.0.2.1", "192.0.2.2"}
	r.SetUsers([]protocol.User{user})
	allowed, err := acquire(r, user, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	kept, err := acquire(r, user, "192.0.2.2", "udp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = acquire(r, user, "192.0.2.3", "tcp"); err == nil {
		t.Fatal("foreign IP admitted")
	}
	user.WhitelistedIPs = []string{"192.0.2.2"}
	r.SetUsers([]protocol.User{user})
	if !allowed.closed || kept.closed {
		t.Fatal("IP removal did not revoke exactly its existing sessions")
	}
	user.WhitelistedIPs = []string{}
	r.SetUsers([]protocol.User{user})
	if !kept.closed {
		t.Fatal("empty enabled list failed open")
	}
	user.WhitelistEnabled = false
	r.SetUsers([]protocol.User{user})
	if lease, err := acquire(r, user, "192.0.2.3", "tcp"); err != nil {
		t.Fatal("global disable did not restore normal admission", err)
	} else {
		lease.Close()
	}
}
