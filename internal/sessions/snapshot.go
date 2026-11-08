package sessions

import (
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type Summary = protocol.UserMetrics

func (r *Registry) Summary() Summary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := Summary{Connections: map[int]int{}, TotalConnections: r.totalConnections(), Rejections: protocol.Clone(r.rejects), Status: map[int]LimitStatus{}, Speed: map[int]SpeedStatus{}}
	s.Rates = protocol.Clone(r.rates)
	s.ActiveIPs = map[int][]string{}
	r.activityHistory.snapshot(&s)
	for id, u := range r.users {
		s.Speed[id] = u.speed.status()
		status := LimitStatus{UserID: id}
		switch {
		case r.paused:
			status.Limited = true
			status.Reason = "storage_backpressure"
		case r.resources >= 100000:
			status.Limited = true
			status.Reason = "agent_capacity"
		case len(u.policy.InboundTags) == 0:
			status.Limited = true
			status.Reason = "ineligible"
		case u.policy.ValidUntil != nil && !u.policy.ValidUntil.After(time.Now()):
			status.Limited = true
			status.Reason = "expired"
		case r.fences[id] > 0 || r.fences[0] > 0 || r.periodFences[accountingKey{id, u.policy.AccountingPeriod}] > 0:
			status.Limited = true
			status.Reason = "block_new"
		case u.policy.BlockNew:
			status.Limited = true
			status.Reason = "block_new"
		case r.bans[id].After(time.Now()):
			status.Limited = true
			status.Reason = "torrent_ban"
		case u.policy.ConnectionLimit > 0 && u.clients >= u.policy.ConnectionLimit:
			status.Limited = true
			status.Reason = "connection_limit"
		case u.policy.ActiveIPLimit > 0 && len(u.ips) >= u.policy.ActiveIPLimit:
			status.Limited = true
			status.Reason = "active_ip_limit"
			status.Scope = "new_ip"
		}
		if status.Scope == "" {
			status.Scope = "new_connection"
		}
		s.Status[id] = status
		if count := r.activeCount(id); count > 0 {
			s.Connections[id] = count
			for ip := range r.activeIPs(id) {
				s.ActiveIPs[id] = append(s.ActiveIPs[id], ip)
			}
			sort.Strings(s.ActiveIPs[id])
		}
	}
	return s
}
func (r *Registry) List(after string, limit int) []Connection {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Connection
	for id, l := range r.connections {
		if id > after && r.activity.connections[id] {
			out = append(out, l.Info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
