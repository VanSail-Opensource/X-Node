package sessions

import "context"

// revokeTransport is called outside the registry lock. An authorization change
// and the hourly controller may both revoke the same transport.
func (l *Lease) revokeTransport() {
	if l.nativeFence != nil {
		defer l.Close()
		l.nativeFenceOnce.Do(l.nativeFence)
		return
	}
	l.Close()
}

func (l *Lease) Close() {
	l.once.Do(func() {
		r := l.registry
		r.mu.Lock()
		delete(r.connections, l.Info.ID)
		l.closed = true
		r.activityHistory.close(l)
		r.invalidateActivity(l)
		l.releaseResource()
		l.user.count--
		if !l.transit {
			l.user.clients--
			l.user.ips[l.Info.SourceIP]--
			if l.user.ips[l.Info.SourceIP] <= 0 {
				delete(l.user.ips, l.Info.SourceIP)
			}
		}
		r.mu.Unlock()
		l.closeHourly()
		if l.cancel != nil {
			l.cancel()
		}
		if !l.tracked {
			l.Finish()
		}
	})
}
func (l *Lease) Account(upload bool, n uint64) {
	l.bytes.Add(n)
	if upload {
		l.user.upload.Add(n)
		if l.accounting != nil {
			l.accounting.upload.Add(n)
		}
	} else {
		l.user.download.Add(n)
		if l.accounting != nil {
			l.accounting.download.Add(n)
		}
	}
}
func (l *Lease) Wait(ctx context.Context, n int) error {
	// Every payload buffer visits this path. A rate policy is replaced
	// atomically, and its own state is synchronized independently.
	return l.user.speed.Load().wait(ctx, n)
}
func (r *Registry) CloseUser(id int, tag string) {
	r.mu.RLock()
	var close []*Lease
	for _, l := range r.connections {
		if l.Info.UserID == id && (tag == "" || l.Info.InboundTag == tag) {
			close = append(close, l)
		}
	}
	r.mu.RUnlock()
	for _, l := range close {
		l.Close()
	}
}
func (r *Registry) CloseConnection(id string) bool {
	r.mu.RLock()
	l := r.connections[id]
	r.mu.RUnlock()
	if l == nil {
		return false
	}
	l.Close()
	return true
}
func (r *Registry) CloseAll() {
	r.mu.RLock()
	var close []*Lease
	for _, l := range r.connections {
		close = append(close, l)
	}
	r.mu.RUnlock()
	for _, l := range close {
		l.Close()
	}
}
func (r *Registry) CloseUserInbound(tag string) {
	r.mu.RLock()
	var close []*Lease
	for _, l := range r.connections {
		if l.Info.InboundTag == tag {
			close = append(close, l)
		}
	}
	r.mu.RUnlock()
	for _, l := range close {
		l.Close()
	}
}
