package sessions

import "context"

// TrackOutbound binds all chained dispatches to the same memory-only lease.
// Fences and registration share the lock, preventing an apply/admission race.
func (l *Lease) TrackOutbound(tag string) bool {
	r := l.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.closed || r.outboundFences[tag] > 0 {
		return false
	}
	if l.outbounds == nil {
		l.outbounds = map[string]bool{}
	}
	l.outbounds[tag] = true
	return true
}

// QuiesceOutbounds fences only affected dispatches and waits for final native
// payload accounting before a handler is replaced. Call release after commit.
func (r *Registry) QuiesceOutbounds(ctx context.Context, tags []string) (func(), error) {
	if len(tags) == 0 {
		return func() {}, nil
	}
	r.mu.Lock()
	if r.outboundFences == nil {
		r.outboundFences = map[string]int{}
	}
	for _, tag := range tags {
		r.outboundFences[tag]++
	}
	var leases []*Lease
	for _, lease := range r.inflight {
		for _, tag := range tags {
			if lease.outbounds[tag] {
				leases = append(leases, lease)
				break
			}
		}
	}
	r.mu.Unlock()
	release := func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, tag := range tags {
			r.outboundFences[tag]--
			if r.outboundFences[tag] == 0 {
				delete(r.outboundFences, tag)
			}
		}
	}
	for _, lease := range leases {
		lease.Close()
	}
	for _, lease := range leases {
		select {
		case <-lease.finished:
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}
