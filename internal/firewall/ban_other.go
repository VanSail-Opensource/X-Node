//go:build !linux

package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (nativeBackend) Bans(context.Context, []protocol.FirewallBan, []protocol.FirewallExemption, []protocol.FirewallSource, bool) error {
	return errors.New("nftables requires Linux")
}
func (g *Guard) RunKernel(ctx context.Context) { <-ctx.Done() }
