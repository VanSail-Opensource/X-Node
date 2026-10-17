package firewall

import (
	"context"
	"os"
)

// EnableConfirmedDNS removes legacy host-wide redirects, regardless of intent.
func (m *Manager) EnableConfirmedDNS(ctx context.Context, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	release, err := m.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	_, err = m.ensureConfirmed(ctx)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return m.backend().DNS(ctx, false)
}
