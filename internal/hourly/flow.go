package hourly

import "time"

type Flow struct {
	controller *Controller
	owner      *ownerState
	binding    BindingKey
	interrupt  func()
	closed     bool
	fenced     bool
	timer      Stopper
	pending    [2]int
	atomic     [2]int
	recent     time.Time
}

func (c *Controller) OpenFlow(binding BindingKey, interrupt func()) (*Flow, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.authorized(binding, c.options.Now()) || interrupt == nil {
		return nil, ErrRevoked
	}
	owner := c.owners[binding.Owner]
	if owner == nil || !reserveCount(&c.flows, c.options.MaxFlows) {
		return nil, ErrCapacity
	}
	flow := &Flow{controller: c, owner: owner, binding: binding, interrupt: interrupt}
	owner.mu.Lock()
	owner.flows[flow] = struct{}{}
	flow.setExpiry(c.authorizations[binding].PaidThrough)
	owner.mu.Unlock()
	return flow, nil
}

// The caller is already closing the native flow. Do not recurse into its hook.
func (f *Flow) Close() {
	o := f.owner
	o.mu.Lock()
	if !f.closed {
		f.closed = true
		if f.timer != nil {
			f.timer.Stop()
		}
		delete(o.flows, f)
		f.pending = [2]int{}
		for p := range o.permits {
			if p.flow == f && !p.started {
				p.cancelLocked()
			}
		}
		f.controller.flows.Add(-1)
		o.signal()
	}
	o.mu.Unlock()
}

func (f *Flow) TryAcquire(direction Direction, want, minAtomic int) (*Permit, Wait, error) {
	if direction > Download || want < 0 || minAtomic < 0 || minAtomic > want || minAtomic > 16384 || want > 0 && minAtomic == 0 {
		return nil, Wait{}, ErrInvalid
	}
	c, o := f.controller, f.owner
	c.mu.RLock()
	defer c.mu.RUnlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	now := c.options.Now()
	if f.closed || f.fenced || !c.authorized(f.binding, now) {
		return nil, Wait{}, ErrRevoked
	}
	b := o.currentBucket(now)
	f.recent, f.pending[direction], f.atomic[direction] = now, min(want, 16384), minAtomic
	wait := Wait{Changed: o.changed}
	if c.session == "" {
		c.notify()
		return nil, wait, nil
	}
	grant := b.grant
	var tokens uint64
	if grant != nil && grant.deadline.After(now) {
		b.refill(now)
		tokens = b.tokens
	} else {
		// Already reserved full-speed bytes remain spendable without a live
		// reduced-rate grant. Never refill or extend expired rate authority.
		grant = nil
	}
	if want == 0 && grant == nil {
		c.notify()
		return nil, wait, nil
	}
	n := min(want, 16384)
	if minAtomic > 1 {
		n = minAtomic
	} // Never split a datagram to fit a token remainder.
	allocations, free := o.creditAllocations(b, uint64(n), c.session)
	reduced := uint64(n) - free
	if reduced > tokens {
		if minAtomic > 1 {
			if grant != nil {
				wait.After = b.delay(reduced - tokens)
			}
			c.notify()
			return nil, wait, nil
		}
		n = int(free + tokens)
		if n == 0 && want != 0 {
			if grant != nil {
				wait.After = b.delay(1)
			}
			c.notify()
			return nil, wait, nil
		}
		allocations, free = o.creditAllocations(b, uint64(n), c.session)
		reduced = uint64(n) - free
	}
	if !reserveCount(&c.permits, c.options.MaxPermits) {
		return nil, Wait{}, ErrCapacity
	}
	if reduced == 0 && n > 0 {
		grant = nil // Fully reserved bytes do not borrow a reduced-rate lease.
	}
	p := &Permit{flow: f, bucket: b, grant: grant, session: c.session, direction: direction, bytes: n, reduced: reduced, credits: allocations}
	for _, a := range allocations {
		a.credit.held += a.bytes
	}
	b.tokens -= reduced
	b.held += reduced
	o.permits[p] = struct{}{}
	f.pending[direction] = 0
	return p, Wait{}, nil
}
