// Package sessions owns user admission and the lifecycle of logical proxy sessions.
package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type Connection struct {
	ID              string    `json:"id"`
	UserID          int       `json:"user_id"`
	InboundTag      string    `json:"inbound_tag"`
	SourceIP        string    `json:"source_ip"`
	Destination     string    `json:"destination"`
	DestinationPort int       `json:"destination_port"`
	Network         string    `json:"network"`
	Started         time.Time `json:"started"`
}
type userState struct {
	policy           protocol.User
	identities       map[string]string
	ips              map[string]int
	count            int
	handlers         int
	speed            *speedPolicy
	upload, download atomic.Uint64
}
type Registry struct {
	mu              sync.RWMutex
	prefix          string
	sequence        uint64
	users           map[int]*userState
	identityAliases map[int]int
	connections     map[string]*Lease
	bans            map[int]time.Time
	ports           []protocol.PortRange
	rejects         map[string]uint64
	paused          bool
	epochs          map[string]string
	OnBan           func(int, time.Time)
	OnReject        func(AdmissionEvent)
	ipBlocks        map[string]protocol.IPBlock
	reportIPs       bool
	accounting      map[accountingKey]*accountingCounters
	inflight        map[string]*Lease
	rates           map[int]protocol.UserRate
	fences          map[int]int
	periodFences    map[accountingKey]int
	activity        activitySnapshot
	closedActivity  map[int]map[string]int
	resources       int
	outboundFences  map[string]int
}
type Lease struct {
	Info                                     Connection
	once                                     sync.Once
	registry                                 *Registry
	user                                     *userState
	cancel                                   func()
	accounting                               *accountingCounters
	accountingPeriod                         string
	tracked                                  bool
	finished                                 chan struct{}
	finishOnce                               sync.Once
	identity                                 string
	outbounds                                map[string]bool
	transit                                  bool
	bytes                                    atomic.Uint64
	sampledBytes                             uint64
	closed, nativeFinished, resourceReleased bool
}

func New() *Registry {
	return &Registry{prefix: state.ID(), users: map[int]*userState{}, connections: map[string]*Lease{}, bans: map[int]time.Time{}, rejects: map[string]uint64{}, epochs: map[string]string{}, ipBlocks: map[string]protocol.IPBlock{}}
}
func sameIdentity(a, b protocol.User) bool {
	a.WhitelistEnabled, b.WhitelistEnabled = false, false
	a.WhitelistedIPs, b.WhitelistedIPs = nil, nil
	a.ID, b.ID = 0, 0
	a.ReplacesID, b.ReplacesID = 0, 0
	a.TransitCredentials, b.TransitCredentials = nil, nil
	a.ValidUntil = nil
	b.ValidUntil = nil
	a.ActiveIPLimit = 0
	a.ConnectionLimit = 0
	a.SpeedLimitMbps = 0
	a.BurstSpeedLimitMbps = 0
	a.SpeedLimitAfterSeconds = 0
	a.SpeedLimitResetSeconds = 0
	a.BlockNew = false
	a.InboundTags = nil
	b.ActiveIPLimit = 0
	b.ConnectionLimit = 0
	b.SpeedLimitMbps = 0
	b.BurstSpeedLimitMbps = 0
	b.SpeedLimitAfterSeconds = 0
	b.SpeedLimitResetSeconds = 0
	b.BlockNew = false
	b.InboundTags = nil
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}
func eligible(u protocol.User, tag string) bool {
	for _, t := range u.InboundTags {
		if t == tag {
			return true
		}
	}
	return false
}
func (r *Registry) SetUsers(users []protocol.User) {
	r.mu.Lock()
	r.rekeyUsers(users)
	r.identityAliases = map[int]int{}
	for _, user := range users {
		if user.ReplacesID != 0 {
			r.identityAliases[user.ReplacesID] = user.ID
		}
	}
	next := map[int]*userState{}
	policies := map[int]protocol.User{}
	for _, p := range users {
		policies[p.ID] = p
		old := r.users[p.ID]
		if old == nil {
			old = &userState{ips: map[string]int{}}
		}
		if old.speed == nil || !sameSpeed(old.policy, p) {
			old.speed = newSpeedPolicy(p)
		}
		next[p.ID] = old
	}
	var close []*Lease
	for _, l := range r.connections {
		p, ok := policies[l.Info.UserID]
		if !ok || !sameIdentity(l.user.policy, p) || !eligible(p, l.Info.InboundTag) || !r.validIdentity(p, l.identity, l.Info.InboundTag) || !l.transit && !sourceAllowed(p, l.Info.SourceIP) {
			close = append(close, l)
		}
	}
	for _, p := range users {
		next[p.ID].policy = protocol.Clone(p)
		next[p.ID].identities = r.identities(p)
	}
	// Retain removed counters until all associated leases finish and the sampler consumes them.
	for id, u := range r.users {
		if _, ok := next[id]; !ok {
			u.policy.InboundTags = nil
			u.identities = nil
			next[id] = u
		}
	}
	r.users = next
	r.mu.Unlock()
	for _, l := range close {
		l.Close()
	}
}
func (r *Registry) identities(u protocol.User) map[string]string {
	out := map[string]string{}
	for _, tag := range u.InboundTags {
		out[tag] = protocol.UserEmail(u, tag)
		if epoch := r.epochs[tag]; epoch != "" {
			out[tag] += "@" + epoch
		}
	}
	return out
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
	transit := u != nil && r.isTransit(u.policy, identity, tag)
	reason := ""
	switch {
	case r.paused:
		reason = "storage_backpressure"
	case r.resources >= 100000:
		reason = "agent_capacity"
	case u == nil || !r.validIdentity(u.policy, identity, tag):
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
	case !transit && u.policy.ConnectionLimit > 0 && r.activeCount(id) >= u.policy.ConnectionLimit:
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
			if r.reportIPs {
				event.SourceIP = ip
			}
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
		u.ips[ip]++
	}
	r.connections[l.Info.ID] = l
	return l, nil
}
func (l *Lease) Close() {
	l.once.Do(func() {
		r := l.registry
		r.mu.Lock()
		delete(r.connections, l.Info.ID)
		l.closed = true
		r.invalidateActivity(l)
		l.releaseResource()
		l.user.count--
		if !l.transit {
			l.user.ips[l.Info.SourceIP]--
			if l.user.ips[l.Info.SourceIP] <= 0 {
				delete(l.user.ips, l.Info.SourceIP)
			}
		}
		r.mu.Unlock()
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
	l.registry.mu.RLock()
	policy := l.user.speed
	l.registry.mu.RUnlock()
	return policy.wait(ctx, n)
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

type Summary = protocol.UserMetrics

func (r *Registry) Summary() Summary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := Summary{Connections: map[int]int{}, Rejections: protocol.Clone(r.rejects), Status: map[int]LimitStatus{}, Speed: map[int]SpeedStatus{}}
	s.Rates = protocol.Clone(r.rates)
	if r.reportIPs {
		s.ActiveIPs = map[int][]string{}
	}
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
		case u.policy.ConnectionLimit > 0 && r.activeCount(id) >= u.policy.ConnectionLimit:
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
			if r.reportIPs {
				for ip := range r.activeIPs(id) {
					s.ActiveIPs[id] = append(s.ActiveIPs[id], ip)
				}
				sort.Strings(s.ActiveIPs[id])
			}
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
