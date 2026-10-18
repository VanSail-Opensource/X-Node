package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/host"
)

// lock bounds contention with an installer or an obsolete rollback helper.
// Its idempotent release permits submitting service work after both locks exit.
func (m *Manager) lock(ctx context.Context) (func(), error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for !m.mu.TryLock() {
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("update transaction busy: %w", ctx.Err())
		case <-timer.C:
		}
	}
	if err := os.MkdirAll(m.Dir, 0700); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	release, err := host.LockContext(ctx, filepath.Join(m.Dir, "lock"))
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("update host lock unavailable: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { release(); m.mu.Unlock() }) }, nil
}
