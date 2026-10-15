package update

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Once boot restoration uses native policy, an older binary cannot safely
// consume the replacement service ordering and empty nftables boot script.
func (m *Manager) nativeFirewallRequired() (bool, error) {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(m.Dir), "firewall", "policy.json"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var p struct {
		Engine int `json:"engine"`
	}
	if json.Unmarshal(b, &p) != nil || p.Engine < 0 || p.Engine > 1 {
		return false, errors.New("invalid firewall compatibility state")
	}
	return p.Engine == 1, nil
}
