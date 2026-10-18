//go:build !linux

package host

import (
	"context"
	"os"
	"time"
)

// Only used by portable fixture tests; deployed agents use kernel-backed flock.
func Lock(path string) (func(), error) {
	return LockContext(context.Background(), path)
}

// LockContext is the cancellable portable fixture equivalent of flock.
func LockContext(ctx context.Context, path string) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if os.IsExist(e) {
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			continue
		} else if e != nil {
			return nil, e
		}
		return func() { _ = f.Close(); _ = os.Remove(path) }, nil
	}
}
