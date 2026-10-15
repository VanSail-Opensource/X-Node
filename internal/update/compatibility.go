package update

import (
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// Pending reports whether the current binary still depends on its rollback watchdog.
func (m *Manager) Pending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	transaction, err := m.read()
	return err == nil && transaction.Status == "pending"
}

// requiredCapabilities prevents downgrades from silently ignoring cached policy or journals.
func (m *Manager) requiredCapabilities() ([]string, error) {
	nativeFirewall, err := m.nativeFirewallRequired()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(m.Dir), "state.json"))
	if os.IsNotExist(err) {
		if nativeFirewall {
			return []string{"native_firewall_v1"}, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot inspect private-state compatibility")
	}
	var data state.Data
	if len(raw) > state.MaxStoreBytes || json.Unmarshal(raw, &data) != nil {
		return nil, errors.New("invalid private-state compatibility data")
	}
	required := map[string]bool{}
	required["native_firewall_v1"] = nativeFirewall
	if len(data.Users) > 0 {
		required["volatile_connection_controls_v1"] = true
	}
	for _, user := range data.Users {
		if user.AccountingPeriod != "" {
			required["traffic_periods_v1"] = true
			required["traffic_period_barriers_v1"] = true
		}
		if user.ValidUntil != nil {
			required["authorization_expiry"] = true
		}
	}
	if len(data.Accounting) > 0 || data.Pending != nil && len(data.Pending.Samples) > 0 {
		required["traffic_periods_v1"] = true
	}
	for _, batch := range data.Backlog {
		if batch == nil {
			return nil, errors.New("invalid accounting backlog")
		}
		if len(batch.Samples) > 0 {
			required["traffic_periods_v1"] = true
		}
	}
	if data.Config != nil && len(data.Config.MemberOutbounds) > 0 {
		required["member_outbound_guards"] = true
	}
	if data.Config != nil {
		tags, err := protocol.AuxiliaryInboundTags(data.Config.Xray)
		if err != nil {
			return nil, err
		}
		if len(tags) > 0 {
			required["native_auxiliary_inbounds_v1"] = true
		}
	}
	var out []string
	for _, key := range []string{"traffic_periods_v1", "traffic_period_barriers_v1", "authorization_expiry", "member_outbound_guards", "volatile_connection_controls_v1", "native_auxiliary_inbounds_v1", "native_firewall_v1"} {
		if required[key] {
			out = append(out, key)
		}
	}
	return out, nil
}

func (m *Manager) checkCapabilities(metadata []byte) error {
	required, err := m.requiredCapabilities()
	if err != nil || len(required) == 0 {
		return err
	}
	var info struct {
		Capabilities []string `json:"capabilities"`
	}
	if json.Unmarshal(metadata, &info) != nil {
		return errors.New("invalid binary capability metadata")
	}
	supported := map[string]bool{}
	for _, capability := range info.Capabilities {
		supported[capability] = true
	}
	for _, capability := range required {
		if !supported[capability] {
			return errors.New("binary cannot preserve current persisted policy")
		}
	}
	return nil
}
