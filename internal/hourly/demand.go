package hourly

import (
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Demand snapshots are coalesced hints. No payload or work queue is retained.
func (c *Controller) PendingDemand(limit int) []protocol.HourlyDemand {
	return c.pendingDemands(min(max(limit, 0), protocol.MaxHourlyItems))
}

// PendingDemands captures every bounded owner once. The transport packs this
// snapshot into bounded frames; a frame limit must not become an admission cap.
func (c *Controller) PendingDemands() []protocol.HourlyDemand {
	return c.pendingDemands(c.options.MaxOwners)
}

func (c *Controller) pendingDemands(limit int) []protocol.HourlyDemand {
	if limit == 0 {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.session == "" {
		return nil
	}
	keys := make([]OwnerKey, 0, len(c.owners))
	for key := range c.owners {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ID == keys[j].ID {
			return keys[i].Generation < keys[j].Generation
		}
		return keys[i].ID < keys[j].ID
	})
	if len(keys) == 0 {
		return nil
	}
	start := int(c.demandCursor.Load() % uint64(len(keys)))
	now := c.options.Now()
	var result []protocol.HourlyDemand
	scanned := 0
	for n := 0; n < len(keys) && len(result) < limit; n++ {
		scanned++
		o := c.owners[keys[(start+n)%len(keys)]]
		o.mu.Lock()
		b := o.currentBucket(now)
		var pending uint64
		var minimum uint32
		active := false
		for flow := range o.flows {
			if flow.closed || flow.fenced || !c.authorized(flow.binding, now) {
				continue
			}
			if !flow.recent.IsZero() && now.Sub(flow.recent) <= 2*time.Second {
				active = true
			}
			for direction, bytes := range flow.pending {
				pending += uint64(bytes)
				if bytes > 0 {
					active = true
					minimum = max(minimum, uint32(flow.atomic[direction]))
				}
			}
		}
		if active && (b.pending == nil || !b.pending.deadline.After(now)) {
			nonce := c.options.Nonce()
			if protocol.ValidStreamID(nonce) {
				b.pending = &pendingDemand{nonce: nonce, started: now, deadline: now.Add(10 * time.Second)}
			}
		}
		if active && b.pending != nil {
			result = append(result, protocol.HourlyDemand{Owner: protocol.HourlyOwner{ID: o.key.ID, Generation: o.key.Generation}, Nonce: b.pending.nonce, LifetimeMillis: 10000, PendingBytes: pending, MinAtomicBytes: minimum})
		}
		o.mu.Unlock()
	}
	c.demandCursor.Add(uint64(scanned))
	return result
}
