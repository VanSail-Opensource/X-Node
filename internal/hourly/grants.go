package hourly

import (
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (c *Controller) ApplyGrant(grant protocol.HourlyGrant) (*Drain, error) {
	if protocol.ValidateHourlyGrant(grant) != nil {
		return nil, ErrInvalid
	}
	c.mu.RLock()
	if c.session == "" || c.session != grant.SessionID {
		c.mu.RUnlock()
		return nil, ErrRevoked
	}
	o := c.owners[OwnerKey{grant.Owner.ID, grant.Owner.Generation}]
	if o == nil {
		c.mu.RUnlock()
		return nil, ErrRevoked
	}
	o.mu.Lock()
	now := c.options.Now()
	b := o.currentBucket(now)
	if b.grant != nil && b.grant.grant == grant && b.grant.deadline.After(now) {
		drain := b.grant.drain
		o.mu.Unlock()
		c.mu.RUnlock()
		return drain, nil
	}
	if b.grant != nil && !b.grant.deadline.After(now) {
		actions := o.fenceFlows(func(*Flow) bool { return true }, nil)
		if b.grant.timer != nil {
			b.grant.timer.Stop()
		}
		b.grant = nil
		b.tokens = 0
		b.remainder = 0
		b.last = now
		o.signal()
		o.mu.Unlock()
		c.mu.RUnlock()
		runFences(actions)
		return nil, ErrRevoked
	}
	pending := b.pending
	if grant.DayUTC != b.scope.DayUTC || grant.Sequence <= o.lastSequence || pending == nil || pending.nonce != grant.Nonce {
		o.mu.Unlock()
		c.mu.RUnlock()
		return nil, ErrRevoked
	}
	deadline := pending.started.Add(time.Duration(grant.LifetimeMillis) * time.Millisecond)
	if deadline.After(pending.deadline) {
		deadline = pending.deadline
	}
	midnight := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
	if midnight.Before(deadline) {
		deadline = midnight
	}
	if !deadline.After(now) {
		b.pending = nil
		o.signal()
		o.mu.Unlock()
		c.mu.RUnlock()
		return nil, ErrRevoked
	}
	b.refill(now)
	old := b.grant
	drain := newDrain()
	var actions []fenceAction
	shrink := old != nil && (grant.RateBytesPerSecond < old.grant.RateBytesPerSecond || grant.BurstBytes < old.grant.BurstBytes)
	if shrink {
		actions = o.fenceFlows(func(*Flow) bool { return true }, drain)
	} else {
		for p := range o.permits {
			if p.bucket == b && !p.started {
				p.cancelLocked()
			}
		}
	}
	if old != nil && old.timer != nil {
		old.timer.Stop()
	}
	next := &grantState{grant: grant, deadline: deadline, drain: drain}
	b.grant, b.pending, o.lastSequence = next, nil, grant.Sequence
	b.tokens = min(b.tokens, b.capacity())
	b.remainder, b.last = 0, now
	next.timer = c.options.AfterFunc(deadline.Sub(now), func() { c.expireGrant(o, next) })
	o.signal()
	o.mu.Unlock()
	c.mu.RUnlock()
	drain.finishAdmission()
	runFences(actions)
	return drain, nil
}
