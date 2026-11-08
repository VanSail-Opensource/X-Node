package protocol

import (
	"encoding/json"
	"errors"
)

// SameUserIdentity preserves the credential/accounting identity comparison used
// by live sessions. Admission controls and independently checked transit grants
// may change without making an owner into another identity.
func SameUserIdentity(a, b User) bool {
	left, err := json.Marshal(userIdentity(a))
	if err != nil {
		return false
	}
	right, err := json.Marshal(userIdentity(b))
	return err == nil && string(left) == string(right)
}

func userIdentity(user User) User {
	user.ID, user.ReplacesID = 0, 0
	user.WhitelistEnabled, user.WhitelistedIPs = false, nil
	user.TransitCredentials, user.ValidUntil, user.InboundTags = nil, nil, nil
	user.ActiveIPLimit, user.ConnectionLimit = 0, 0
	user.SpeedLimitMbps, user.BurstSpeedLimitMbps = 0, 0
	user.SpeedLimitAfterSeconds, user.SpeedLimitResetSeconds = 0, 0
	user.BlockNew = false
	return user
}

// UserReplacementIDs validates actual moves against the original snapshots.
// Historical replaces_id hints with an absent old subject grant no new proof:
// ordinary same-ID renewals and credential rotation must continue to work.
func UserReplacementIDs(previous, next []User) (map[int]int, error) {
	before, err := replacementUserIndex(previous)
	if err != nil {
		return nil, err
	}
	after, err := replacementUserIndex(next)
	if err != nil {
		return nil, err
	}
	replacements, sources := map[int]int{}, map[int]bool{}
	for _, user := range next {
		if user.ReplacesID == 0 {
			continue
		}
		if user.ReplacesID < 0 || user.ReplacesID == user.ID || sources[user.ReplacesID] {
			return nil, errors.New("invalid or duplicate identity replacement")
		}
		sources[user.ReplacesID] = true
		old, exists := before[user.ReplacesID]
		if !exists {
			continue
		}
		if _, retained := after[old.ID]; retained {
			return nil, errors.New("identity replacement source is still active")
		}
		if _, occupied := before[user.ID]; occupied {
			return nil, errors.New("identity replacement target is occupied")
		}
		if old.UUID == "" && len(old.Credentials) == 0 || !SameUserIdentity(old, user) {
			return nil, errors.New("identity replacement changed credentials or accounting period")
		}
		replacements[old.ID] = user.ID
	}
	return replacements, nil
}

func replacementUserIndex(users []User) (map[int]User, error) {
	index := make(map[int]User, len(users))
	for _, user := range users {
		if _, exists := index[user.ID]; user.ID <= 0 || exists {
			return nil, errors.New("invalid or duplicate identity subject")
		}
		index[user.ID] = user
	}
	return index, nil
}
