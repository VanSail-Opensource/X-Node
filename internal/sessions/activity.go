package sessions

// activitySnapshot is replaced at each sampling boundary. Closed leases are
// invalidated separately without mutating the published interval's counters.
type activitySnapshot struct {
	connections map[string]bool
	counts      map[int]int
	ips         map[int]map[string]int
}

// SampleActivity measures live logical flows, independently of accounting and
// native handler lifetimes. There is deliberately no inactivity grace period.
func (r *Registry) SampleActivity() {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := activitySnapshot{map[string]bool{}, map[int]int{}, map[int]map[string]int{}}
	for id, lease := range r.connections {
		bytes := lease.bytes.Load()
		increased := bytes > lease.sampledBytes
		lease.sampledBytes = bytes
		if !increased || lease.transit {
			continue
		}
		next.connections[id] = true
		next.counts[lease.Info.UserID]++
		ips := next.ips[lease.Info.UserID]
		if ips == nil {
			ips = map[string]int{}
			next.ips[lease.Info.UserID] = ips
		}
		ips[lease.Info.SourceIP]++
	}
	r.activity, r.closedActivity = next, nil
}

func (r *Registry) activeCount(user int) int {
	count := r.activity.counts[user]
	for _, closed := range r.closedActivity[user] {
		count -= closed
	}
	return max(0, count)
}

// totalConnections requires the registry lock and excludes internal transit hops.
// Logical close removes a flow even if its native handler is still finishing.
func (r *Registry) totalConnections() map[int]int {
	counts := map[int]int{}
	for _, lease := range r.connections {
		if !lease.transit {
			counts[lease.Info.UserID]++
		}
	}
	return counts
}

func (r *Registry) activeIPs(user int) map[string]int {
	ips := map[string]int{}
	for ip, count := range r.activity.ips[user] {
		if remaining := count - r.closedActivity[user][ip]; remaining > 0 {
			ips[ip] = remaining
		}
	}
	return ips
}

func (r *Registry) invalidateActivity(lease *Lease) {
	if !r.activity.connections[lease.Info.ID] {
		return
	}
	if r.closedActivity == nil {
		r.closedActivity = map[int]map[string]int{}
	}
	if r.closedActivity[lease.Info.UserID] == nil {
		r.closedActivity[lease.Info.UserID] = map[string]int{}
	}
	r.closedActivity[lease.Info.UserID][lease.Info.SourceIP]++
}

// releaseResource requires the registry lock. Logical close cannot release an
// unfinished native handler's hard capacity reservation or accounting barrier.
func (l *Lease) releaseResource() {
	if l.closed && (!l.tracked || l.nativeFinished) && !l.resourceReleased {
		l.registry.resources--
		l.resourceReleased = true
	}
}
