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
	// The transaction is atomically replaced; do not join the installer here.
	// Pending is called from the main loop and reconnect hello during shutdown.
	transaction, err := m.read()
	return err == nil && transaction.Status == "pending"
}

// requiredCapabilities prevents downgrades from silently ignoring cached policy or journals.
func (m *Manager) requiredCapabilities() ([]string, error) {
	nativeFirewall, err := m.nativeFirewallRequired()
	if err != nil {
		return nil, err
	}
	controlRequired := false
	ownershipRequired := false
	compatRequired := false
	if _, e := os.Stat(filepath.Join(filepath.Dir(m.Dir), "firewall", "original-services.json")); e == nil {
		ownershipRequired = true
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if _, e := os.Stat(filepath.Join(filepath.Dir(m.Dir), "firewall", "original-compat.json")); e == nil {
		compatRequired = true
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if _, e := os.Stat(filepath.Join(filepath.Dir(m.Dir), "firewall", "controlled-v1")); e == nil {
		controlRequired = true
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(m.Dir), "state.json"))
	if os.IsNotExist(err) {
		caps := []string{}
		if nativeFirewall {
			caps = append(caps, "native_firewall_v1")
		}
		if controlRequired {
			caps = append(caps, "firewall_control_v1")
		}
		if ownershipRequired {
			caps = append(caps, "host_firewall_ownership_v1")
		}
		if compatRequired {
			caps = append(caps, "xtables_compat_snapshot_v1")
		}
		return caps, nil
	}
	if err != nil {
		return nil, errors.New("cannot inspect private-state compatibility")
	}
	var data state.Data
	if len(raw) > state.MaxStoreBytes || json.Unmarshal(raw, &data) != nil {
		return nil, errors.New("invalid private-state compatibility data")
	}
	required := map[string]bool{}
	required["firewall_control_v1"] = controlRequired
	required["native_firewall_v1"] = nativeFirewall
	required["host_firewall_ownership_v1"] = ownershipRequired
	required["xtables_compat_snapshot_v1"] = compatRequired
	if len(data.Users) > 0 {
		required["volatile_connection_controls_v1"] = true
	}
	for _, user := range data.Users {
		if len(user.TransitCredentials) > 0 {
			required["transit_credentials_v1"] = true
		}
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
	for _, config := range []*protocol.Config{data.Config, data.DesiredConfig} {
		if config == nil {
			continue
		}
		if len(config.MemberOutbounds) > 0 {
			required["member_outbound_guards"] = true
		}
		if config.Firewall.SourceGeoIP != nil {
			required["source_geoip_firewall_v1"] = true
		}
		for _, certificate := range config.Certificates {
			if certificate.Config.CertMode == "file" && certificate.Config.Domain == "" { required["node_file_certificates_v1"] = true }
		}
		if len(config.BlockedDomains) > 0 {
			required["shared_domain_blocks_v1"] = true
		}
		var native struct {
			Geodata struct {
				IntervalHours *int `json:"interval_hours"`
			} `json:"geodata"`
		}
		if json.Unmarshal(config.Xray, &native) == nil && native.Geodata.IntervalHours != nil {
			required["geodata_interval_v1"] = true
		}
		if config.Firewall.MasterControlled {
			required["firewall_control_v1"] = true
		}
		if config.DNS.Redirect {
			required["xray_scoped_dns_v1"] = true
		}
		tags, err := protocol.AuxiliaryInboundTags(config.Xray)
		if err != nil {
			return nil, err
		}
		if len(tags) > 0 {
			required["native_auxiliary_inbounds_v1"] = true
		}
	}
	var out []string
	for _, key := range []string{"traffic_periods_v1", "traffic_period_barriers_v1", "authorization_expiry", "member_outbound_guards", "volatile_connection_controls_v1", "native_auxiliary_inbounds_v1", "native_firewall_v1", "xray_scoped_dns_v1", "firewall_control_v1", "host_firewall_ownership_v1", "xtables_compat_snapshot_v1", "transit_credentials_v1", "source_geoip_firewall_v1", "shared_domain_blocks_v1", "geodata_interval_v1"} {
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
