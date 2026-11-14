package hourly

import "time"

// Publication never calls a native hook while holding either controller lock.
func (c *Controller) ApplyAuthorization(sequence, revision uint64, bindings []Authorization) bool {
	c.mu.Lock()
	if c.stopped || sequence <= c.sequence || revision < c.revision || len(bindings) > c.options.MaxFlows {
		c.mu.Unlock()
		return false
	}
	next := make(map[BindingKey]Authorization, len(bindings))
	keys := map[OwnerKey]bool{}
	for _, binding := range bindings {
		if !validBinding(binding.Key) || binding.PaidThrough.IsZero() {
			c.mu.Unlock()
			return false
		}
		if _, exists := next[binding.Key]; exists {
			c.mu.Unlock()
			return false
		}
		next[binding.Key], keys[binding.Key.Owner] = binding, true
	}
	missing := 0
	var prune []OwnerKey
	for key, owner := range c.owners {
		if keys[key] {
			continue
		}
		owner.mu.Lock()
		if len(owner.flows)+len(owner.permits)+len(owner.credits)+len(owner.samples) == 0 {
			prune = append(prune, key)
		}
		owner.mu.Unlock()
	}
	for key := range keys {
		if c.owners[key] == nil {
			missing++
		}
	}
	if len(c.owners)-len(prune)+missing > c.options.MaxOwners {
		c.mu.Unlock()
		return false
	}
	for _, key := range prune {
		delete(c.owners, key)
	}
	for key := range keys {
		if c.owners[key] == nil {
			c.owners[key] = c.newOwner(key)
		}
	}
	c.authorizations, c.sequence, c.revision = next, sequence, revision
	now := c.options.Now()
	var actions []fenceAction
	for _, owner := range c.owners {
		owner.mu.Lock()
		actions = append(actions, owner.fenceFlows(func(flow *Flow) bool {
			a, ok := next[flow.binding]
			return !ok || !a.PaidThrough.After(now)
		}, nil)...)
		for flow := range owner.flows {
			if a, ok := next[flow.binding]; ok && a.PaidThrough.After(now) && !flow.fenced {
				flow.setExpiry(a.PaidThrough)
			}
		}
		owner.signal()
		owner.mu.Unlock()
	}
	c.mu.Unlock()
	runFences(actions)
	return true
}

// An empty/changed session discards all live grants, never durable obligations.
func (c *Controller) SetSession(session string) *Drain {
	c.mu.Lock()
	if c.stopped || c.session == session {
		c.mu.Unlock()
		return completedDrain()
	}
	c.session = session
	var actions []fenceAction
	drain := newDrain()
	for _, owner := range c.owners {
		owner.mu.Lock()
		if b := owner.bucket; b != nil {
			if b.grant != nil && b.grant.timer != nil {
				b.grant.timer.Stop()
			}
			b.grant, b.pending = nil, nil
			b.tokens, b.remainder = 0, 0
		}
		for _, credit := range owner.credits {
			credit.frozen = true
		}
		actions = append(actions, owner.retirePermits(func(*Permit) bool { return true }, drain)...)
		owner.incarnation++
		owner.bucket = &bucket{scope: Scope{Owner: owner.key, DayUTC: c.options.Now().UTC().Format(time.DateOnly)}, incarnation: owner.incarnation, last: c.options.Now()}
		owner.lastSequence = 0
		owner.signal()
		owner.mu.Unlock()
	}
	c.mu.Unlock()
	drain.finishAdmission()
	runFences(actions)
	return drain
}

func (c *Controller) authorized(key BindingKey, now time.Time) bool {
	a, ok := c.authorizations[key]
	return !c.stopped && ok && a.PaidThrough.After(now)
}
