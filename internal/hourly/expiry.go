package hourly

import "time"

// ExpirePaid shares the timer's native fence with maintenance. Recheck the live
// authorization so a stale expiry observation cannot revoke a paid renewal.
func (c *Controller) ExpirePaid(now time.Time) {
	c.mu.RLock()
	var actions []fenceAction
	for _, owner := range c.owners {
		owner.mu.Lock()
		expired := false
		for flow := range owner.flows {
			if !flow.closed && !flow.fenced && !c.authorized(flow.binding, now) {
				expired = true
				break
			}
		}
		if expired {
			actions = append(actions, owner.fenceFlows(func(flow *Flow) bool {
				return !c.authorized(flow.binding, now)
			}, nil)...)
			owner.signal()
		}
		owner.mu.Unlock()
	}
	c.mu.RUnlock()
	runFences(actions)
}

func (f *Flow) setExpiry(paid time.Time) {
	if f.timer != nil {
		f.timer.Stop()
	}
	f.timer = f.controller.options.AfterFunc(paid.Sub(f.controller.options.Now()), func() {
		c, o := f.controller, f.owner
		c.mu.RLock()
		o.mu.Lock()
		a, ok := c.authorizations[f.binding]
		var actions []fenceAction
		if !f.closed && (!ok || a.PaidThrough.Equal(paid) && !paid.After(c.options.Now())) {
			actions = o.fenceFlows(func(candidate *Flow) bool { return candidate == f }, nil)
			o.signal()
		}
		o.mu.Unlock()
		c.mu.RUnlock()
		runFences(actions)
	})
}

func (c *Controller) expirePermit(p *Permit, deadline time.Time) {
	o := p.flow.owner
	c.mu.RLock()
	o.mu.Lock()
	var actions []fenceAction
	if p.started && !p.finished && !deadline.After(c.options.Now()) {
		actions = o.fence(func(candidate *Permit) bool { return candidate == p }, "", nil)
		o.signal()
	}
	o.mu.Unlock()
	c.mu.RUnlock()
	runFences(actions)
}

func (c *Controller) expireGrant(o *ownerState, grant *grantState) {
	c.mu.RLock()
	o.mu.Lock()
	var actions []fenceAction
	if o.bucket != nil && o.bucket.grant == grant && !grant.deadline.After(c.options.Now()) {
		actions = o.fenceFlows(func(*Flow) bool { return true }, nil)
		o.bucket.grant = nil
		o.bucket.tokens, o.bucket.remainder = 0, 0
		o.signal()
	}
	o.mu.Unlock()
	c.mu.RUnlock()
	runFences(actions)
}
