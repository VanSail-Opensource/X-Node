//go:build !linux

package firewall

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/host"
)

func lockContext(ctx context.Context, path string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return host.Lock(path)
}
