package update

import (
	"encoding/json"
	"errors"
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
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		var record struct {
			Policy protocol.FirewallPolicy `json:"policy"`
		}
		if len(raw) > protocol.MaxFrameBytes || json.Unmarshal(raw, &record) != nil {
			return false, errors.New("invalid firewall port compatibility state")
		}
		needed = needed || record.Policy.UsesPortRanges()
	}
	return needed, nil
}
