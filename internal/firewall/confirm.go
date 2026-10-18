package firewall

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

func (m *Manager) Confirm(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	p, err := readRecord(m.path())
	if err != nil {
		return err
	}
	if p.ID != id {
		return errors.New("firewall confirmation ID differs")
	}
	if p.Status == "confirmed" {
		return nil
	}
	if p.Status != "pending" {
		return errors.New("firewall transaction is no longer pending")
	}
	if !p.Deadline.After(time.Now()) {
		return errors.Join(errors.New("firewall confirmation expired"), m.recover(ctx, &p, true))
	}
	pending, err := m.upgradePending()
	if err != nil {
		return err
	}
	if pending {
		return errors.New("binary upgrade must be confirmed before firewall migration")
	}
	if !p.Ownership {
		if err = m.prepareServices(ctx, &p); err != nil {
			return err
		}
		if err = writeRecord(m.path(), p); err != nil {
			return err
		}
		if err = m.takeControl(ctx, p); err != nil {
			return errors.Join(err, m.recover(ctx, &p, true))
		}
	}
	if p.Engine == 0 {
		if err = m.backupUnits(&p); err != nil {
			return err
		}
		p.Engine = 1
		if err = writeRecord(m.path(), p); err != nil {
			return err
		}
		if err = m.backend().Reconcile(ctx, p.Policy, p.Redirect, p.SSH); err != nil {
			return errors.Join(err, m.recover(ctx, &p, !errors.Is(err, errUnchanged)))
		}
	}
	if err = m.installBoot(ctx); err != nil {
		return errors.Join(err, m.recover(ctx, &p, true))
	}
	if err = m.enableNFTService(ctx, p.Services); err != nil {
		return errors.Join(err, m.recover(ctx, &p, true))
	}
	if err = m.persistForwarding(p.Pending); err != nil {
		return errors.Join(err, m.recover(ctx, &p, true))
	}
	if !p.Deadline.After(time.Now()) || ctx.Err() != nil {
		return errors.Join(errors.New("firewall confirmation interrupted or expired"), ctx.Err(), m.recover(ctx, &p, true))
	}
	// If pending.json does not commit, the watchdog restores previous-policy.json.
	p.Status = "confirmed"
	if err = writeRecord(filepath.Join(m.Dir, "policy.json"), p); err != nil {
		p.Status = "pending"
		return errors.Join(err, m.recover(ctx, &p, true))
	}
	if err = writeRecord(m.path(), p); err != nil {
		p.Status = "pending"
		return errors.Join(err, m.recover(ctx, &p, true))
	}
	// The durable confirmed marker makes a racing watchdog harmless.
	_, _ = m.Runner.Run(ctx, "systemctl", "stop", p.Unit+".timer")
	return nil
}
