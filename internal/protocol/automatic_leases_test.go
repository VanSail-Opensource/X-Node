package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAutomaticLeaseContractBoundsAndExactAddresses(t *testing.T) {
	now := time.Now().UTC()
	base := AutomaticLeaseUpdate{Epoch: "master", Leases: []AutomaticLeaseGrant{{IP: "2001:4860::8", Generation: 9007199254740993, Until: now.Add(time.Hour)}}}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AutomaticLeaseUpdate
	if err := Decode(raw, &decoded); err != nil || decoded.Validate(now) != nil || decoded.Leases[0].Generation != base.Leases[0].Generation {
		t.Fatal("lease contract lost generation precision", err)
	}
	for _, ip := range []string{"2001:4860::/64", "::ffff:8.8.8.8", "127.0.0.1", "192.168.1.1", "100.64.0.1", "2001:db8::1", "240.0.0.1", "fe80::1%eth0"} {
		update := Clone(base)
		update.Leases[0].IP = ip
		if update.Validate(now) == nil {
			t.Fatal("noncanonical/nonpublic/range grant accepted", ip)
		}
	}
	for _, mutate := range []func(*AutomaticLeaseUpdate){
		func(u *AutomaticLeaseUpdate) { u.Epoch = "" },
		func(u *AutomaticLeaseUpdate) { u.Leases[0].Generation = 0 },
		func(u *AutomaticLeaseUpdate) { u.Leases[0].Until = now.Add(3 * 8760 * time.Hour) },
		func(u *AutomaticLeaseUpdate) { u.Leases = append(u.Leases, u.Leases[0]) },
		func(u *AutomaticLeaseUpdate) { u.Leases = make([]AutomaticLeaseGrant, MaxAutomaticLeaseBatch+1) },
	} {
		update := Clone(base)
		mutate(&update)
		if update.Validate(now) == nil {
			t.Fatal("invalid lease batch accepted")
		}
	}
}
