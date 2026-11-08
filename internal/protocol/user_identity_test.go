package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func replacementUserFixture(id int) User {
	return User{ID: id, UUID: "owner-credential", AccountingPeriod: "paid-period", InboundTags: []string{"in"},
		Credentials: map[string]json.RawMessage{"in": json.RawMessage(`{"password":"native-test-credential"}`)}}
}

func TestSameUserIdentityKeepsCredentialAndAccountingBoundaries(t *testing.T) {
	base := replacementUserFixture(1)
	unchanged := Clone(base)
	controls := Clone(base)
	deadline := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	controls.ID, controls.ReplacesID = 20, 1
	controls.WhitelistEnabled, controls.WhitelistedIPs = true, []string{"192.0.2.1"}
	controls.TransitCredentials = []TransitCredential{{SourceNodeID: "new-peer", InboundTag: "in"}}
	controls.ValidUntil, controls.InboundTags = &deadline, []string{"other"}
	controls.ActiveIPLimit, controls.ConnectionLimit = 1, 2
	controls.SpeedLimitMbps, controls.BurstSpeedLimitMbps = 3, 4
	controls.SpeedLimitAfterSeconds, controls.SpeedLimitResetSeconds, controls.BlockNew = 5, 6, true
	if !SameUserIdentity(base, controls) || !SameUserIdentity(controls, base) {
		t.Fatal("mutable admission controls changed the shared identity predicate")
	}
	if !reflect.DeepEqual(base, unchanged) {
		t.Fatal("identity comparison mutated caller-owned credentials")
	}
	for _, test := range []struct {
		name string
		edit func(*User)
	}{
		{"uuid", func(user *User) { user.UUID = "different-credential" }},
		{"native credential", func(user *User) { user.Credentials["in"] = json.RawMessage(`{"password":"rotated"}`) }},
		{"accounting period", func(user *User) { user.AccountingPeriod = "next-period" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			other := Clone(base)
			test.edit(&other)
			if SameUserIdentity(base, other) || SameUserIdentity(other, base) {
				t.Fatal("different credential/accounting identity compared equal")
			}
		})
	}
	invalid := Clone(base)
	invalid.Credentials["in"] = json.RawMessage(`{`)
	if SameUserIdentity(invalid, invalid) {
		t.Fatal("serialization failure became identity equality")
	}
}
