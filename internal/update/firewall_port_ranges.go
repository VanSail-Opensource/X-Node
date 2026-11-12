package update

import (
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Policy and rollback snapshots can outlive the main authorization state.
// Protect every retained restore candidate from a binary that ignores ranges.
func (m *Manager) firewallPortRangesRequired() (bool, error) {
	dir := filepath.Join(filepath.Dir(m.Dir), "firewall")
	needed := false
	for _, name := range []string{"policy.json", "pending.json", "previous-policy.json", "candidate.json"} {
		raw, err := state.ReadRecoveryFile(filepath.Join(dir, name), protocol.MaxFrameBytes)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		var record *struct {
			Policy *protocol.FirewallPolicy `json:"policy"`
		}
		if json.Unmarshal(raw, &record) != nil || record == nil || record.Policy == nil {
			return false, errors.New("invalid firewall port compatibility state")
		}
		needed = needed || record.Policy.UsesPortRanges()
	}
	return needed, nil
}
