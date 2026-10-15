package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"
)

const bootUnit = `[Unit]
Description=Restore confirmed X-Node firewall policy
After=local-fs.target systemd-sysctl.service nftables.service
Before=x-node.service
ConditionPathExists=/var/lib/x-node/firewall/policy.json

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xnodectl firewall-restore
UMask=0077

[Install]
WantedBy=multi-user.target
`
const bootConfig = "# X-Node restores its confirmed JSON firewall policy through x-node-firewall.service.\n"
const bootDropin = "[Unit]\nWants=x-node-firewall.service\nAfter=x-node-firewall.service\n"

func (m *Manager) unitPath() string {
	if m.UnitPath != "" {
		return m.UnitPath
	}
	return "/etc/systemd/system/x-node-firewall.service"
}
func (m *Manager) dropinPath() string {
	return filepath.Join(filepath.Dir(m.unitPath()), "x-node.service.d", "90-firewall.conf")
}
func (m *Manager) backupUnits(p *record) error {
	for i, target := range []string{m.unitPath(), m.dropinPath()} {
		f, err := m.backup(target, filepath.Join(m.Dir, fmt.Sprintf("previous-unit-%d", i)))
		if err != nil {
			return err
		}
		p.Files = append(p.Files, f)
	}
	return nil
}
func (m *Manager) installBoot(ctx context.Context) error {
	for _, f := range []struct{ path, body string }{{m.ConfigPath, bootConfig}, {m.unitPath(), bootUnit}, {m.dropinPath(), bootDropin}} {
		mode := os.FileMode(0644)
		if f.path == m.ConfigPath {
			mode = 0600
		}
		if err := os.MkdirAll(filepath.Dir(f.path), 0755); err != nil {
			return err
		}
		if err := state.AtomicWrite(f.path, []byte(f.body), mode); err != nil {
			return err
		}
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := m.Runner.Run(ctx, "systemctl", "enable", "x-node-firewall.service")
	return err
}
func (m *Manager) upgradePending() (bool, error) {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(m.Dir), "updates", "transaction.json"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var t struct {
		Status string `json:"status"`
	}
	if err = json.Unmarshal(b, &t); err != nil {
		return false, err
	}
	return t.Status == "pending", nil
}

// Migrate defers boot persistence until the binary upgrade is confirmed.
func (m *Manager) Migrate(ctx context.Context, dnsReady bool) error {
	p, err := m.migrationPolicy(ctx)
	if err != nil || p == nil {
		return err
	}
	tx, err := m.apply(ctx, "boot-migration-"+state.ID(), p.Policy, p.Redirect, p.Redirect && dnsReady)
	if err != nil {
		return err
	}
	return m.Confirm(ctx, tx.ID)
}
func (m *Manager) migrationPolicy(ctx context.Context) (*record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	pending, err := m.upgradePending()
	if err != nil || pending {
		return nil, err
	}
	current, err := readRecord(m.path())
	if err == nil && current.Status == "pending" {
		return nil, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	p, err := readRecord(filepath.Join(m.Dir, "policy.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if p.Engine == 1 {
		matches := true
		for _, f := range []struct{ path, body string }{{m.ConfigPath, bootConfig}, {m.unitPath(), bootUnit}, {m.dropinPath(), bootDropin}} {
			b, err := os.ReadFile(f.path)
			if err != nil || !bytes.Equal(b, []byte(f.body)) {
				matches = false
			}
		}
		if matches {
			return nil, nil
		}
	}
	return &p, nil
}
