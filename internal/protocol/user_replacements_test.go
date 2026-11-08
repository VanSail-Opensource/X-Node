package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUserReplacementUsesOriginalCredentialAndPeriod(t *testing.T) {
	old := replacementUserFixture(10)
	next := Clone(old)
	next.ID, next.ReplacesID, next.BlockNew = 20, 10, true
	previous, desired := []User{old}, []User{next}
	before, after := Clone(previous), Clone(desired)
	mapping, err := UserReplacementIDs(previous, desired)
	if err != nil || len(mapping) != 1 || mapping[10] != 20 {
		t.Fatalf("valid replacement was not identified: %v, %v", mapping, err)
	}
	if !reflect.DeepEqual(previous, before) || !reflect.DeepEqual(desired, after) {
		t.Fatal("replacement validation changed caller-owned snapshots")
	}
	old.UUID, next.UUID = "", ""
	if mapping, err := UserReplacementIDs([]User{old}, []User{next}); err != nil || mapping[10] != 20 {
		t.Fatal("native credential-only identity could not be preserved", err)
	}
}

func TestHistoricalReplacementHintsDoNotBlockRenewalOrMintProof(t *testing.T) {
	current := replacementUserFixture(20)
	current.ReplacesID = 10 // The panel retains this from member_identity_aliases.
	for _, test := range []struct {
		name string
		edit func(*User)
	}{
		{"repeated snapshot", func(*User) {}},
		{"paid successor", func(user *User) { user.AccountingPeriod = "renewed-paid-period" }},
		{"rotated credential", func(user *User) {
			user.UUID = "rotated-uuid"
			user.Credentials["in"] = json.RawMessage(`{"password":"rotated"}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := Clone(current)
			test.edit(&next)
			mapping, err := UserReplacementIDs([]User{current}, []User{next})
			if err != nil || len(mapping) != 0 {
				t.Fatalf("historical alias blocked ordinary renewal/rotation or minted a transfer: %v, %v", mapping, err)
			}
		})
	}
	if mapping, err := UserReplacementIDs(nil, []User{current}); err != nil || len(mapping) != 0 {
		t.Fatal("an unknown old subject supplied identity proof", mapping, err)
	}
}

func TestUserReplacementRejectsMalformedOrOccupiedSubjects(t *testing.T) {
	old := replacementUserFixture(10)
	target := Clone(old)
	target.ID, target.ReplacesID = 20, 10
	for _, test := range []struct {
		name string
		edit func(*[]User, *[]User)
	}{
		{"uuid changed", func(_ *[]User, next *[]User) { (*next)[0].UUID = "other" }},
		{"native credential changed", func(_ *[]User, next *[]User) { (*next)[0].Credentials["in"] = json.RawMessage(`{"password":"other"}`) }},
		{"period changed", func(_ *[]User, next *[]User) { (*next)[0].AccountingPeriod = "other-period" }},
		{"source still active", func(_ *[]User, next *[]User) { *next = append(*next, Clone(old)) }},
		{"target occupied by another owner", func(previous *[]User, _ *[]User) {
			occupied := replacementUserFixture(20)
			occupied.UUID = "other"
			*previous = append(*previous, occupied)
		}},
		{"target already occupied", func(previous *[]User, _ *[]User) { *previous = append(*previous, replacementUserFixture(20)) }},
		{"duplicate source", func(_ *[]User, next *[]User) {
			duplicate := Clone((*next)[0])
			duplicate.ID = 30
			*next = append(*next, duplicate)
		}},
		{"same numeric ID", func(_ *[]User, next *[]User) { (*next)[0].ID = 10 }},
		{"negative source", func(_ *[]User, next *[]User) { (*next)[0].ReplacesID = -1 }},
		{"zero target", func(_ *[]User, next *[]User) { (*next)[0].ID = 0 }},
		{"duplicate prior ID", func(previous *[]User, _ *[]User) { *previous = append(*previous, Clone(old)) }},
		{"duplicate next ID", func(_ *[]User, next *[]User) { *next = append(*next, Clone((*next)[0])) }},
		{"no prior credential", func(previous *[]User, next *[]User) {
			(*previous)[0].UUID, (*next)[0].UUID = "", ""
			(*previous)[0].Credentials, (*next)[0].Credentials = nil, nil
		}},
		{"invalid prior credential", func(previous *[]User, next *[]User) {
			(*previous)[0].Credentials["in"], (*next)[0].Credentials["in"] = json.RawMessage(`{`), json.RawMessage(`{`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous, next := []User{Clone(old)}, []User{Clone(target)}
			test.edit(&previous, &next)
			if mapping, err := UserReplacementIDs(previous, next); err == nil || len(mapping) != 0 {
				t.Fatalf("malformed replacement was accepted: %v, %v", mapping, err)
			}
		})
	}
}
