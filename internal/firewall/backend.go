// Package firewall owns the host firewall through atomic nftables transactions.
package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Backend reconciles policy without committing intermediate kernel changes.
// Implementations must preserve unchanged stateful sets and counter objects.
type Backend interface {
	Reconcile(context.Context, protocol.FirewallPolicy, bool, []int) error
	DNS(context.Context, bool) error
}

func validate(p protocol.FirewallPolicy, ssh []int) error {
	if err := (protocol.Config{Xray: []byte(`{"inbounds":[]}`), Users: []protocol.User{}, Firewall: p}).Validate(); err != nil {
		return err
	}
	if len(ssh) == 0 && len(p.SSHPorts) == 0 {
		return errors.New("SSH listening ports must be known")
	}
	for _, port := range ssh {
		if port < 1 || port > 65535 {
			return errors.New("invalid discovered SSH port")
		}
	}
	return nil
}

func (m *Manager) backend() Backend {
	if m.Backend != nil {
		return m.Backend
	}
	return nativeBackend{}
}
