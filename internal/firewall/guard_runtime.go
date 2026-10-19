package firewall

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"sync"
	"time"
)

func (g *Guard) Run(ctx context.Context, send func(protocol.Message, bool) bool) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	nextReport := time.Time{}
	nextCleanup := time.Now().Add(time.Minute)
	for {
		select {
		case <-ctx.Done():
			g.mu.Lock()
			_ = g.compact()
			g.mu.Unlock()
			return
		case ids := <-g.acks:
			g.mu.Lock()
			_ = g.appendJournal(journalRecord{Ack: ids})
			g.mu.Unlock()
		case <-ticker.C:
			g.mu.Lock()
			err := g.flushPending()
			if err == nil {
				err = g.processHits(time.Now().UTC())
			}
			if err == nil {
				err = g.expire(time.Now().UTC())
			}
			if err == nil && (g.dirty || g.sourcesDirty) && !g.applying {
				g.applying = true
				workers.Add(1)
				go func() {
					defer workers.Done()
					g.mu.Lock()
					e := g.enforce(ctx)
					g.applying = false
					if e != nil {
						g.kernelError = "FIREWALL_SYNC_PENDING"
					} else {
						g.kernelError = ""
					}
					g.mu.Unlock()
				}()
			}
			if err == nil && (g.journalBytes > 32<<20 || time.Since(g.compacted) > time.Hour) {
				err = g.compact()
			}
			if err != nil {
				send(protocol.New("agent.error", "", 0, map[string]string{"error": "firewall durable state remains pending"}), false)
			}
			if !time.Now().Before(nextReport) {
				if policy := g.policy.Load(); policy != nil && policy.MasterControlled {
					status := g.statusLocked()
					send(protocol.New("firewall.events", "", 0, protocol.FirewallEvents{State: &status, InstanceID: g.state.EventNamespace, Events: g.pendingEvents(protocol.MaxFirewallEventsPerFrame), Dropped: g.dropped.Load(), KernelReady: g.kernelReady.Load()}), true)
				}
				nextReport = time.Now().Add(5 * time.Second)
			}
			g.mu.Unlock()
			if !time.Now().Before(nextCleanup) {
				g.cleanupExpiredSources(ctx)
				nextCleanup = time.Now().Add(time.Minute)
			}
		}
	}
}
