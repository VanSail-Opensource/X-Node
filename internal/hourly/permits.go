package hourly

import "time"

type Permit struct {
	flow              *Flow
	bucket            *bucket
	grant             *grantState
	session           string
	direction         Direction
	bytes             int
	reduced           uint64
	credits           []creditAllocation
	started, finished bool
	timer             Stopper
	drains            []*Drain
}

func (p *Permit) Bytes() int { return p.bytes }

// Begin is the synchronous payload admission boundary. The caller already owns
// exactly Bytes real payload bytes; delivery success is not another quota event.
func (p *Permit) Begin() error {
	c, o := p.flow.controller, p.flow.owner
	c.mu.RLock()
	defer c.mu.RUnlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	now := c.options.Now()
	if p.started || p.finished {
		return ErrRevoked
	}
	valid := !p.flow.closed && !p.flow.fenced && c.authorized(p.flow.binding, now) && c.session != "" && p.session == c.session && p.bucket.scope.DayUTC == now.UTC().Format(time.DateOnly)
	if p.grant != nil {
		valid = valid && p.grant == p.bucket.grant && p.grant.grant.SessionID == c.session && p.grant.deadline.After(now)
	} else {
		valid = valid && p.reduced == 0
	}
	for _, a := range p.credits {
		valid = valid && !a.credit.frozen && a.credit.installed.marker.active()
	}
	if !valid {
		p.cancelLocked()
		o.signal()
		return ErrRevoked
	}
	if err := o.recordSample(p, now); err != nil {
		p.cancelLocked()
		o.signal()
		return err
	}
	// Settle elapsed time while this ticket still occupies burst capacity. Time
	// spent holding an unstarted ticket cannot refill the capacity it releases.
	p.bucket.refill(now)
	p.started = true
	p.bucket.held -= p.reduced
	for _, a := range p.credits {
		a.credit.held -= a.bytes
		a.credit.admitted[p.direction] += a.bytes
	}
	deadline := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
	if p.grant != nil && p.grant.deadline.Before(deadline) {
		deadline = p.grant.deadline
	}
	if paid := c.authorizations[p.flow.binding].PaidThrough; paid.Before(deadline) {
		deadline = paid
	}
	p.timer = c.options.AfterFunc(deadline.Sub(now), func() { c.expirePermit(p, deadline) })
	o.changedOnly()
	o.wakeLowCredit(p.bucket, c.session)
	return nil
}

func (p *Permit) Complete(_ Outcome) {
	o := p.flow.owner
	o.mu.Lock()
	if !p.finished {
		if !p.started {
			p.cancelLocked()
			o.signal()
		} else {
			p.finishLocked()
			o.changedOnly()
		}
	}
	o.mu.Unlock()
}

func (p *Permit) cancelLocked() {
	if p.finished {
		return
	}
	if !p.started {
		p.bucket.refill(p.flow.controller.options.Now())
		p.bucket.held -= p.reduced
		p.bucket.tokens = min(p.bucket.tokens+p.reduced, p.bucket.capacity())
		for _, a := range p.credits {
			a.credit.held -= a.bytes
		}
	}
	p.finishLocked()
}

func (p *Permit) finishLocked() {
	p.finished = true
	if p.timer != nil {
		p.timer.Stop()
	}
	delete(p.flow.owner.permits, p)
	p.flow.controller.permits.Add(-1)
	for _, drain := range p.drains {
		drain.finishAdmission()
	}
	p.drains = nil
}
