package update

import (
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"
)

// Once boot restoration uses native policy, an older binary cannot safely
// consume the replacement service ordering and empty nftables boot script.
func (m *Manager) nativeFirewallRequired() (bool, error) {
	b, err := state.ReadRecoveryFile(filepath.Join(filepath.Dir(m.Dir), "firewall", "policy.json"), protocol.MaxFrameBytes)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var p *struct {
		Engine int `json:"engine"`
	}
	if json.Unmarshal(b, &p) != nil || p == nil || p.Engine < 0 || p.Engine > 1 {
		return false, errors.New("invalid firewall compatibility state")
	}
	return p.Engine == 1, nil
}

func (m *Manager) xtablesCompatibilityRequired() (bool, error) {
	raw, err := state.ReadRecoveryFile(filepath.Join(filepath.Dir(m.Dir), "firewall", "original-compat.json"), protocol.MaxFrameBytes)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var snapshots []json.RawMessage
	if json.Unmarshal(raw, &snapshots) != nil || snapshots == nil {
		return false, errors.New("invalid original xtables compatibility evidence")
	}
	// New original snapshots include a durable empty manifest before their
	// completion marker. Empty evidence needs no xtables recovery extension.
	return len(snapshots) > 0, nil
}
