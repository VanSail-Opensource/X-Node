//go:build linux

package firewall

import (
	"errors"
	"golang.org/x/sys/unix"
)

func bulkFreeSpace(dir string, extra int64) error {
	var info unix.Statfs_t
	if err := unix.Statfs(dir, &info); err != nil {
		return err
	}
	if uint64(extra)+(16<<20) > info.Bavail*uint64(info.Bsize) {
		return errors.New("firewall staging would exhaust disk reserve")
	}
	return nil
}
