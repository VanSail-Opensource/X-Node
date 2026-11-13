package protocol

import "testing"

func TestUserDeltaRejectsAmbiguousIdentitiesBeforeMerge(t *testing.T) {
	for _, delta := range []UsersDelta{
		{Upsert: []User{{ID: 1}, {ID: 1}}},
		{Upsert: []User{{ID: 0}}},
		{Remove: []int{0}}, {Remove: []int{-1}}, {Remove: []int{1, 1}},
		{Upsert: []User{{ID: 1}}, Remove: []int{1}},
	} {
		if err := delta.Validate(); err == nil {
			t.Fatal("ambiguous authorization delta accepted", delta)
		}
	}
	if err := (UsersDelta{Upsert: []User{{ID: 2}}, Remove: []int{1}}).Validate(); err != nil {
		t.Fatal("disjoint authorization delta rejected", err)
	}
}
