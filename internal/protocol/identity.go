package protocol

import "errors"

func validateRekeys(users []User) error {
	seen := map[int]bool{}
	for _, user := range users {
		if user.ReplacesID < 0 || user.ReplacesID == user.ID || user.ReplacesID > 0 && seen[user.ReplacesID] {
			return errors.New("invalid identity replacement")
		}
		if user.ReplacesID > 0 {
			seen[user.ReplacesID] = true
		}
	}
	return nil
}
