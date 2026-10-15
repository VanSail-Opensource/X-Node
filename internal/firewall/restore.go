package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"
)

// RestoreFile retains the CLI entry point, restoring live policy through Go.
func (m *Manager) RestoreFile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := readRecord(m.path())
	if err == nil && tx.Status == "pending" {
		if err = m.recover(ctx, &tx, true); err != nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	p, err := readRecord(filepath.Join(m.Dir, "policy.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = m.applyForwarding(ctx, p.Pending); err != nil {
		return err
	}
	return m.backend().Reconcile(ctx, p.Policy, false, p.SSH)
}

func (m *Manager) RestoreOriginal(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := readRecord(m.path())
	if err == nil && tx.Status == "pending" {
		if err = m.recover(ctx, &tx, true); err != nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	path := filepath.Join(m.Dir, "original.nft")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = m.Runner.Run(ctx, "nft", "-f", path); err != nil {
		return err
	}
	original, err := m.originalForwarding()
	if err == nil {
		if _, err = m.Runner.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward="+original.IPv4, "net.ipv6.conf.all.forwarding="+original.IPv6); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = os.Remove(m.forwardingPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = os.Remove(m.dropinPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = state.AtomicWrite(m.ConfigPath, b, 0600); err != nil {
		return err
	}
	tx.Status = "unmanaged"
	if err = writeRecord(m.path(), tx); err != nil {
		return err
	}
	err = os.Remove(filepath.Join(m.Dir, "policy.json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (m *Manager) ensureConfirmed(ctx context.Context) (record, error) {
	p, err := readRecord(filepath.Join(m.Dir, "policy.json"))
	if err != nil {
		return p, err
	}
	tx, err := readRecord(m.path())
	if err == nil && tx.Status == "pending" {
		return p, errors.New("cannot change DNS during a pending firewall transaction")
	}
	if err != nil && !os.IsNotExist(err) {
		return p, err
	}
	return p, nil
}
