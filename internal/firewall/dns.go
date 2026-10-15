package firewall

import (
	"context"
	"os"
)

// EnableConfirmedDNS changes only the confirmed DNS chain, after readiness.
func (m *Manager) EnableConfirmedDNS(ctx context.Context, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	p, err := m.ensureConfirmed(ctx)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return m.backend().DNS(ctx, enabled && p.Redirect)
}
