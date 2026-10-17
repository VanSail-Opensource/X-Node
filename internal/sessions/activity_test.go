package sessions

import (
	"context"
	"encoding/json"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
)

func TestSampledActivityWithoutGrace(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			r, u := New(), testUser()
			u.ConnectionLimit, u.ActiveIPLimit = 1, 0
			r.SetUsers([]protocol.User{u})
			lease, err := acquire(r, u, "192.0.2.1", network)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			r.SampleActivity()
			if r.Summary().Connections[1] != 0 || len(r.List("", 100)) != 0 {
				t.Fatal("unused lease was active")
			}
			lease.Account(true, 12)
			r.SampleActivity()
			if r.Summary().Connections[1] != 1 || len(r.ActiveIPs(1)) != 1 || len(r.List("", 100)) != 1 {
				t.Fatal("sample projections diverged")
			}
			if _, err := acquire(r, u, "192.0.2.2", network); err == nil {
				t.Fatal("sampled limit was ignored")
			}
			r.SampleActivity()
			if r.Summary().Connections[1] != 0 || len(r.ActiveIPs(1)) != 0 {
				t.Fatal("idle lease retained a grace period")
			}
			lease.Account(false, 4)
			r.SampleActivity()
			lease.Close()
			if r.Summary().Connections[1] != 0 || len(r.ActiveIPs(1)) != 0 {
				t.Fatal("closed lease remained active")
			}
			if r.Counters()[1] != [2]uint64{12, 4} {
				t.Fatal("activity expiry changed accounting")
			}
		})
	}
}

func TestAuthenticatedTransitAccountingAndRevocation(t *testing.T) {
	r, u := New(), testUser()
	u.AccountingPeriod = "paid-period"
	binding := protocol.TransitCredential{SourceNodeID: "source-node", InboundTag: "in", Generation: "revision-1", Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440011"}`)}
	u.TransitCredentials = []protocol.TransitCredential{binding}
	u.BlockNew = true
	r.SetUsers([]protocol.User{u})
	if _, err := acquire(r, u, "192.0.2.1", "tcp"); err == nil {
		t.Fatal("ordinary client bypassed global control")
	}
	lease, err := r.AcquireTracked(context.Background(), u.ID, protocol.TransitEmail(u.ID, binding), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Finish()
	lease.Account(true, 100)
	r.SampleActivity()
	if r.Summary().Connections[1] != 0 || len(r.ActiveIPs(1)) != 0 || r.Counters()[1][0] != 100 {
		t.Fatal("transit affected client counts or lost traffic")
	}
	u.TransitCredentials = nil
	r.SetUsers([]protocol.User{u})
	if r.resources != 1 {
		t.Fatal("logical revocation released unfinished resource")
	}
	lease.Account(false, 17)
	lease.Finish()
	if r.resources != 0 || r.AccountingCounters()[0].Download != 17 {
		t.Fatal("native completion or late accounting was lost")
	}
	if _, err := r.Acquire(context.Background(), u.ID, protocol.TransitEmail(u.ID, binding), "in", "192.0.2.1", "example.com:443", "tcp", 443, nil); err == nil {
		t.Fatal("revoked transit credential accepted")
	}
}
