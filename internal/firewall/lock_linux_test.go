package firewall

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCrossProcessLockObservesCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	release, err := lockContext(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err = lockContext(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked lock ignored cancellation", err)
	}
}
