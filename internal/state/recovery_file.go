package state

import (
	"errors"
	"io"
	"math"
	"os"
	"syscall"
)

// ReadRecoveryFile reads a bounded regular evidence file without modifying it.
// The initial type/size check and descriptor read limit both precede allocation;
// nonblocking/no-follow open prevents FIFO or symlink swaps from hanging recovery.
func ReadRecoveryFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 {
		return nil, errors.New("invalid recovery file limit")
	}
	checked, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !checked.Mode().IsRegular() || checked.Size() > limit {
		return nil, errors.New("invalid recovery file")
	}
	// The agent is Linux-only. Nonblocking/no-follow flags also protect the
	// interval between Lstat and open from a swapped FIFO or symbolic link.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(checked, info) || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid recovery file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("invalid recovery file")
	}
	return b, nil
}
