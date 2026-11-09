package agent

import (
	"encoding/hex"
	"encoding/json"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Even uncertain certificate mutations retain only allowlisted public outcome
// facts. PEM, provider responses and private candidate objects cannot survive.
func certificateJobFacts(value any) any {
	if value == nil {
		return nil
	}
	raw, err := marshalJobBounded(value, 2048)
	if err != nil {
		return nil
	}
	var result protocol.CertificateRunResult
	if json.Unmarshal(raw, &result) != nil || !protocol.ValidName(result.ProfileID) || result.Action != "issue" && result.Action != "renew" {
		return nil
	}
	if result.Fingerprint != "" {
		if decoded, err := hex.DecodeString(result.Fingerprint); err != nil || len(decoded) != 32 {
			return nil
		}
	}
	return result
}
