package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func (m *Manager) Rollback(ctx context.Context) error { return m.RollbackID(ctx, "") }
func (m *Manager) RollbackID(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	p, err := readRecord(m.path())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.Status != "pending" || id != "" && p.ID != id {
		return nil
	}
	return m.recover(ctx, &p, true)
}
func (m *Manager) recover(parent context.Context, p *record, kernel bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
	defer cancel()
	var failures []error
	if kernel {
		if _, err := m.Runner.Run(ctx, "nft", "-f", p.Backup); err != nil {
			failures = append(failures, err)
		}
	}
	if p.ForwardIPv4 != "" && p.ForwardIPv6 != "" {
		if _, err := m.Runner.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward="+p.ForwardIPv4, "net.ipv6.conf.all.forwarding="+p.ForwardIPv6); err != nil {
			failures = append(failures, err)
		}
	}
	backups := []fileBackup{
		{Target: m.ConfigPath, Backup: p.ConfigBackup, Existed: p.ConfigExisted},
		{Target: filepath.Join(m.Dir, "policy.json"), Backup: p.PolicyBackup, Existed: p.PolicyExisted},
		{Target: m.forwardingPath(), Backup: filepath.Join(m.Dir, "previous-forwarding.conf"), Existed: p.ForwardConfigExisted},
	}
	for _, f := range backups {
		if err := restoreBackup(f, 0600); err != nil {
			failures = append(failures, err)
		}
	}
	for _, f := range p.Files {
		if err := restoreBackup(f, 0644); err != nil {
			failures = append(failures, err)
		}
	}
	if len(p.Files) > 0 {
		if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	p.Status = "rolled_back"
	if !kernel {
		p.Status = "failed"
	}
	return writeRecord(m.path(), *p)
}
