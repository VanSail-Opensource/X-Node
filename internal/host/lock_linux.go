//go:build linux

package host

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

func Lock(path string) (func(), error) {
	return LockContext(context.Background(), path)
}

// LockContext waits for a host lock without ignoring shutdown or its deadline.
func LockContext(ctx context.Context, path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	for {
		if e = ctx.Err(); e != nil {
			_ = f.Close()
			return nil, e
		}
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			_ = f.Close()
			return nil, e
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}
