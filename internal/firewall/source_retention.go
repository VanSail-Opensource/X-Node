package firewall

import (
	"context"
	"time"
)

func (g *Guard) cleanupExpiredSources(ctx context.Context) {
	if !g.sourceMu.TryLock() {
		return
	}
	defer g.sourceMu.Unlock()
	child, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	release, err := g.lockBulk(child)
	if err != nil {
		return
	}
	defer release()
	if err = g.pruneAbandonedStages(child, time.Now()); err != nil {
		return
	}
	if err = g.cleanupSourceFiles(); err != nil {
		g.mu.Lock()
		g.kernelError = "FIREWALL_CLEANUP_PENDING"
		g.mu.Unlock()
	}
}
