// Package sessions owns user admission and the lifecycle of logical proxy sessions.
package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func New() *Registry {
	return &Registry{prefix: state.ID(), users: map[int]*userState{}, connections: map[string]*Lease{}, bans: map[int]time.Time{}, rejects: map[string]uint64{}, epochs: map[string]string{}, ipBlocks: map[string]protocol.IPBlock{}}
}
func sameIdentity(a, b protocol.User) bool { return protocol.SameUserIdentity(a, b) }
func eligible(u protocol.User, tag string) bool {
	for _, t := range u.InboundTags {
		if t == tag {
			return true
		}
	}
	return false
}
func (r *Registry) SetInboundEpochs(epochs map[string]string) {
	r.mu.Lock()
	var close []*Lease
	for _, l := range r.connections {
		if r.epochs[l.Info.InboundTag] != epochs[l.Info.InboundTag] {
			close = append(close, l)
		}
	}
	r.epochs = protocol.Clone(epochs)
	for _, u := range r.users {
		u.identities = r.identities(u.policy)
	}
	r.mu.Unlock()
	for _, l := range close {
		l.Close()
	}
}
func (r *Registry) PruneCounters() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, u := range r.users {
		if len(u.policy.InboundTags) == 0 && u.count == 0 && u.handlers == 0 {
			delete(r.users, id)
		}
	}
}
func (r *Registry) Pause(v bool) { r.mu.Lock(); r.paused = v; r.mu.Unlock() }
func (r *Registry) SetPorts(ports []protocol.PortRange) {
	r.mu.Lock()
	r.ports = protocol.Clone(ports)
	var close []*Lease
	for _, l := range r.connections {
		if r.blocked(l.Info.DestinationPort, l.Info.Network) {
			close = append(close, l)
		}
	}
	r.mu.Unlock()
	for _, l := range close {
		l.Close()
	}
}
func (r *Registry) blocked(port int, network string) bool {
	for _, p := range r.ports {
		if port >= p.From && port <= p.To && (p.Network == "" || p.Network == network) {
			return true
		}
	}
	return false
}

func (r *Registry) acquire(ctx context.Context, id int, identity, tag, ip, destination, network string, port int, cancel func(), tracked bool) (*Lease, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, errors.New("invalid source address")
	}
	ip = addr.Unmap().String()
	r.mu.Lock()
	var rejection *AdmissionEvent
	callback := r.OnReject
	defer func() {
		r.mu.Unlock()
		if rejection != nil && callback != nil {
			callback(*rejection)
		}
	}()
	u := r.users[id]
	if mapped := r.rekeyIdentity(id, identity, tag); mapped != 0 {
		id, u = mapped, r.users[mapped]
	}
	transit, valid := false, false
	if u != nil {
		transit, valid = u.identities.lookup(identity, tag)
	}
	reason := ""
	switch {
	case r.paused:
		reason = "storage_backpressure"
	case r.resources >= 100000:
		reason = "agent_capacity"
	case u == nil || !valid:
		reason = "ineligible"
	case u.policy.ValidUntil != nil && !u.policy.ValidUntil.After(time.Now()):
		reason = "expired"
	case r.fences[id] > 0 || r.fences[0] > 0 || r.periodFences[accountingKey{id, u.policy.AccountingPeriod}] > 0:
		reason = "block_new"
	case u.policy.BlockNew && !transit:
		reason = "block_new"
	case !transit && !sourceAllowed(u.policy, ip):
		reason = "source_not_whitelisted"
	case r.bans[id].After(time.Now()):
		reason = "torrent_ban"
	case r.blockedIP(id, ip, time.Now()):
		reason = "ip_temp_block"
	case r.blocked(port, network):
		reason = "blocked_port"
	case !transit && u.policy.ConnectionLimit > 0 && u.clients >= u.policy.ConnectionLimit:
		reason = "connection_limit"
	case !transit && u.policy.ActiveIPLimit > 0 && u.ips[ip] == 0 && len(u.ips) >= u.policy.ActiveIPLimit:
		reason = "active_ip_limit"
	}
	if reason != "" {
		r.rejects[reason]++
		if r.OnReject != nil {
			event := AdmissionEvent{UserID: id, Limited: true, Reason: reason, Scope: "new_connection"}
			if reason == "active_ip_limit" {
				event.Scope = "new_ip"
			}
			event.SourceIP = ip
			rejection = &event
		}
		return nil, errors.New(reason)
	}
	r.sequence++
	l := &Lease{Info: Connection{ID: fmt.Sprintf("%s:%d", r.prefix, r.sequence), UserID: id, InboundTag: tag, SourceIP: ip, Destination: destination, DestinationPort: port, Network: network, Started: time.Now().UTC()}, registry: r, user: u, cancel: cancel, identity: identity, transit: transit}
	r.initializeAccounting(l, tracked)
	r.resources++
	u.count++
	if !transit {
		u.clients++
		u.ips[ip]++
	}
	r.connections[l.Info.ID] = l
	return l, nil
}
func (r *Registry) Ban(id int, until time.Time) {
	r.mu.Lock()
	r.bans[id] = until
	cb := r.OnBan
	r.mu.Unlock()
	r.CloseUser(id, "")
	if cb != nil {
		cb(id, until)
	}
}
func (r *Registry) RestoreBans(bans map[int]time.Time) {
	r.mu.Lock()
	r.bans = protocol.Clone(bans)
	if r.bans == nil {
		r.bans = map[int]time.Time{}
	}
	r.mu.Unlock()
}
func (r *Registry) ExpireBans(now time.Time) []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []int
	for id, t := range r.bans {
		if !t.After(now) {
			delete(r.bans, id)
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	return ids
}
func (r *Registry) Counters() state.Traffic {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := state.Traffic{}
	for id, u := range r.users {
		out[id] = [2]uint64{u.upload.Load(), u.download.Load()}
	}
	return out
}
