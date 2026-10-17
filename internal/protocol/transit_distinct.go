package protocol

import (
	"encoding/json"
	"errors"
	"strings"
)

// Primary and transit authentication must never share a reusable secret on one
// inbound, even when their native account objects have different optional fields.
func validateDistinctTransitAccounts(users []User) error {
	used := map[string]bool{}
	keys := func(tag string, raw json.RawMessage, fallback string) []string {
		var object map[string]any
		_ = json.Unmarshal(raw, &object)
		var result []string
		for _, field := range []string{"id", "password", "auth", "pass"} {
			if value, ok := object[field].(string); ok && value != "" {
				if field == "id" {
					value = strings.ToLower(value)
				}
				result = append(result, tag+"\x00"+field+"\x00"+value)
			}
		}
		if len(result) == 0 && fallback != "" {
			for _, field := range []string{"id", "password", "auth", "pass"} {
				result = append(result, tag+"\x00"+field+"\x00"+strings.ToLower(fallback))
			}
		}
		return result
	}
	for _, user := range users {
		for _, tag := range user.InboundTags {
			for _, key := range keys(tag, user.Credentials[tag], user.UUID) {
				used[key] = true
			}
		}
	}
	for _, user := range users {
		for _, binding := range user.TransitCredentials {
			identities := keys(binding.InboundTag, binding.Credential, "")
			if len(identities) == 0 {
				return errors.New("transit credential has no supported authentication secret")
			}
			for _, key := range identities {
				if used[key] {
					return errors.New("transit authentication must be distinct from other accounts")
				}
				used[key] = true
			}
		}
	}
	return nil
}
