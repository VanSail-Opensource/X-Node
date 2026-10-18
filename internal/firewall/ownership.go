package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type originalServices struct {
	Services []serviceState `json:"services"`
	UFW      *fileBackup    `json:"ufw,omitempty"`
}

func (m *Manager) ufwConfig() string {
	if m.UFWConfigPath != "" {
		return m.UFWConfigPath
	}
	return "/etc/ufw/ufw.conf"
}

func (m *Manager) prepareServices(ctx context.Context, tx *record) error {
	services, err := m.serviceStates(ctx)
	if err != nil {
		return err
	}
	tx.Services = services
	tx.Ownership = true
	original := originalServices{Services: services}
	originalPath := filepath.Join(m.Dir, "original-services.json")
	_, err = os.Stat(originalPath)
	first := os.IsNotExist(err)
	if err != nil && !first {
		return err
	}
	for _, s := range services {
		if s.Name != "ufw.service" {
			continue
		}
		f, err := m.backup(m.ufwConfig(), filepath.Join(m.Dir, "previous-ufw.conf"))
		if err != nil || !f.Existed {
			return errors.Join(errors.New("cannot back up UFW configuration"), err)
		}
		tx.Files = append(tx.Files, f)
		if first {
			f, err = m.backup(m.ufwConfig(), filepath.Join(m.Dir, "original-ufw.conf"))
			if err != nil {
				return err
			}
			original.UFW = &f
		}
	}
	if first {
		b, err := json.Marshal(original)
		if err != nil {
			return err
		}
		return state.AtomicWrite(originalPath, b, 0600)
	}
	return nil
}

// Install policy first, then stop the competing owner. UFW's stop operation can
// flush its iptables tables; the independent inet x_node policy stays enforced.
func (m *Manager) takeControl(ctx context.Context, tx record) error {
	for _, s := range tx.Services {
		if s.Name != "ufw.service" {
			continue
		}
		current, err := m.serviceStates(ctx)
		if err != nil {
			return err
		}
		var owner serviceState
		for _, unit := range current {
			if unit.Name == s.Name {
				owner = unit
			}
		}
		b, err := os.ReadFile(m.ufwConfig())
		if err != nil {
			return err
		}
		if strings.HasPrefix(owner.Enabled, "masked") && !owner.Active && ufwDisabled(b) {
			return nil
		}
		if !strings.HasPrefix(owner.Enabled, "masked") {
			if _, err := m.Runner.Run(ctx, "systemctl", "mask", s.Name); err != nil {
				return err
			}
		}
		// CLI-enabled UFW can enforce rules while its oneshot unit is inactive.
		// Disable it explicitly so iptables-legacy rules cannot shadow x_node.
		if _, err := m.Runner.Run(ctx, "ufw", "--force", "disable"); err != nil {
			return err
		}
		if owner.Active {
			if _, err := m.Runner.Run(ctx, "systemctl", "stop", s.Name); err != nil {
				return err
			}
		}
		b, err = os.ReadFile(m.ufwConfig())
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		found := false
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "ENABLED=") {
				lines[i] = "ENABLED=no"
				found = true
			}
		}
		if !found {
			lines = append(lines, "ENABLED=no")
		}
		if err = state.AtomicWrite(m.ufwConfig(), []byte(strings.Join(lines, "\n")), 0644); err != nil {
			return err
		}
		// Remove any compatibility tables created by UFW's stop handler in one
		// more atomic reconciliation, retaining existing x_node dynamic objects.
		return m.backend().Reconcile(ctx, tx.Policy, false, tx.SSH)
	}
	return nil
}

func (m *Manager) enableNFTService(ctx context.Context, services []serviceState) error {
	for _, s := range services {
		if s.Name != "nftables.service" {
			continue
		}
		if _, err := m.Runner.Run(ctx, "systemctl", "unmask", s.Name); err != nil {
			return err
		}
		if _, err := m.Runner.Run(ctx, "systemctl", "unmask", "--runtime", s.Name); err != nil {
			return err
		}
		if s.Enabled != "static" && s.Enabled != "indirect" {
			if _, err := m.Runner.Run(ctx, "systemctl", "enable", s.Name); err != nil {
				return err
			}
		}
		_, err := m.Runner.Run(ctx, "systemctl", "start", s.Name)
		return err
	}
	return nil
}

func (m *Manager) restoreOriginalServices(ctx context.Context) error {
	b, err := os.ReadFile(filepath.Join(m.Dir, "original-services.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved originalServices
	if err = json.Unmarshal(b, &saved); err != nil {
		return err
	}
	if saved.UFW != nil {
		if err = restoreBackup(*saved.UFW, 0644); err != nil {
			return err
		}
	}
	if err = m.restoreServices(ctx, saved.Services); err != nil {
		return err
	}
	return m.restoreUFWEnforcement(ctx, saved.Services)
}

func (m *Manager) restoreUFWEnforcement(ctx context.Context, services []serviceState) error {
	for _, s := range services {
		if s.Name != "ufw.service" {
			continue
		}
		b, err := os.ReadFile(m.ufwConfig())
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == "ENABLED=yes" {
				_, err := m.Runner.Run(ctx, "ufw", "--force", "enable")
				return err
			}
		}
	}
	return nil
}
