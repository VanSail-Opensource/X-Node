//go:build !linux

package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type nativeBackend struct{ dir string }

func (nativeBackend) Reconcile(context.Context, protocol.FirewallPolicy, bool, []int) error {
	return errors.New("nftables requires Linux")
}
func (nativeBackend) DNS(context.Context, bool) error { return errors.New("nftables requires Linux") }
