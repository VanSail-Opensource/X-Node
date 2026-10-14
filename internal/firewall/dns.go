package firewall

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"
)

// EnableConfirmedDNS activates only the previously confirmed resolver redirect.
// Boot restoration deliberately leaves this chain empty until the agent probes DNS readiness.
func (m *Manager) EnableConfirmedDNS(ctx context.Context, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, e := readPending(filepath.Join(m.Dir, "policy.json"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	b := []byte("flush chain inet x_node dns_output\nadd rule inet x_node dns_output meta nfproto ipv4 udp dport 53 counter name dns_redirects redirect to :53\nadd rule inet x_node dns_output meta nfproto ipv4 tcp dport 53 counter name dns_redirects redirect to :53\nadd rule inet x_node dns_output meta nfproto ipv6 udp dport 53 counter name dns_redirects redirect to :53\nadd rule inet x_node dns_output meta nfproto ipv6 tcp dport 53 counter name dns_redirects redirect to :53\n")
	if !p.Redirect || !enabled {
		b = []byte("flush chain inet x_node dns_output\n")
	}
	path := filepath.Join(m.Dir, "dns-ready.nft")
	if e = state.AtomicWrite(path, b, 0600); e != nil {
		return e
	}
	if _, e = m.Runner.Run(ctx, "nft", "-c", "-f", path); e != nil {
		return e
	}
	_, e = m.Runner.Run(ctx, "nft", "-f", path)
	return e
}
