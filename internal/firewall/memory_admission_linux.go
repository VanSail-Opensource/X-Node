//go:build linux

package firewall

import (
	"context"
	"errors"

	"github.com/shirou/gopsutil/v4/mem"
)

func admitRangeSet(ctx context.Context, count int) error {
	if count == 0 {
		return nil
	}
	info, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return err
	}
	// Both interval endpoints, tree/extension overhead and userspace headroom.
	// Available memory already excludes the currently enforced generation.
	if uint64(count)*256+(64<<20) > info.Available {
		return errors.New("insufficient memory to stage firewall ranges")
	}
	return nil
}
