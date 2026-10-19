package update

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
)

func (m *Manager) Confirm(ctx context.Context) error {
	if e := os.MkdirAll(m.Dir, 0700); e != nil {
		return e
	}
	unlock, e := m.lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	t, e := m.read()
	if os.IsNotExist(e) {
		m.pruneDownloads()
		return nil
	}
	if e != nil {
		return e
	}
	if t.Status != "pending" || t.Version != m.Current {
		if t.Status != "pending" {
			m.pruneDownloads()
		}
		return nil
	}
	t.Status = "confirmed"
	if e = m.write(t); e != nil {
		return e
	}
	m.pruneDownloads()
	unlock()
	if t.Unit != "" {
		_, _ = m.Runner.Run(ctx, "systemctl", "--no-block", "stop", t.Unit+".timer")
	}
	return nil
}
func (m *Manager) Rollback(ctx context.Context) error {
	unlock, e := m.lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	t, e := m.read()
	if e != nil {
		return e
	}
	if t.Status == "rolled_back" || t.Status == "failed" {
		return nil
	}
	if e = m.restore(ctx, &t); e != nil {
		return e
	}
	unlock()
	if t.Unit != "" {
		_, _ = m.Runner.Run(ctx, "systemctl", "--no-block", "stop", t.Unit+".timer")
	}
	return m.restart(ctx)
}
func (m *Manager) RollbackPending(ctx context.Context) error {
	unlock, e := m.lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	t, e := m.read()
	if e != nil {
		return e
	}
	if t.Status != "pending" {
		return nil
	}
	if e = m.restore(ctx, &t); e != nil {
		return e
	}
	unlock()
	if t.Unit != "" {
		_, _ = m.Runner.Run(ctx, "systemctl", "--no-block", "stop", t.Unit+".timer")
	}
	return m.restart(ctx)
}
func (m *Manager) restore(ctx context.Context, t *Transaction) error {
	if required, err := m.requiredCapabilities(); err != nil {
		return err
	} else if len(required) > 0 {
		metadata, err := m.Runner.Run(ctx, t.NodePath+".old", "--version")
		if err != nil {
			return err
		}
		if err = m.checkCapabilities(metadata); err != nil {
			return err
		}
	}
	for _, target := range []string{t.NodePath, t.CLIPath} {
		b, e := os.ReadFile(target + ".old")
		if e != nil {
			return e
		}
		if e = state.AtomicWrite(target, b, 0755); e != nil {
			return e
		}
	}
	t.Status = "rolled_back"
	if e := m.write(*t); e != nil {
		return e
	}
	return nil
}
