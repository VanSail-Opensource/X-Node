package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// TransitCredential is master-only authorization for an owner-scoped peer hop.
// Its secret is never a member subscription credential or a source-IP heuristic.
type TransitCredential struct {
	SourceNodeID string          `json:"source_node_id"`
	InboundTag   string          `json:"inbound_tag"`
	Generation   string          `json:"generation"`
	Credential   json.RawMessage `json:"credential"`
}

// TransitEmail binds native authentication to the owner and peer generation.
func TransitEmail(userID int, binding TransitCredential) string {
	raw, _ := json.Marshal(binding)
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("user@%d:%s", userID, hex.EncodeToString(digest[:16]))
}

func validateTransit(user User) error {
	if len(user.TransitCredentials) > 128 {
		return errors.New("too many transit credentials")
	}
	seen := map[string]bool{}
	for _, binding := range user.TransitCredentials {
		key := binding.SourceNodeID + "\x00" + binding.InboundTag
		if !ValidName(binding.SourceNodeID) || !ValidName(binding.Generation) || !ValidName(binding.InboundTag) || seen[key] {
			return errors.New("invalid transit binding")
		}
		seen[key] = true
		eligible := false
		for _, tag := range user.InboundTags {
			eligible = eligible || tag == binding.InboundTag
		}
		var credential map[string]any
		if !eligible || len(binding.Credential) == 0 || len(binding.Credential) > 8192 || json.Unmarshal(binding.Credential, &credential) != nil || len(credential) == 0 {
			return errors.New("invalid transit credential")
		}
		for _, key := range []string{"email", "level"} {
			if _, exists := credential[key]; exists {
				return errors.New("transit account metadata is managed")
			}
		}
	}
	return nil
}
