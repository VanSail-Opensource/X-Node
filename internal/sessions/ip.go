package sessions

import (
	"errors"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"net/netip"
	"sort"
	"time"
)

type AdmissionEvent struct {
	UserID   int    `json:"user_id"`
	Limited  bool   `json:"limited"`
	Reason   string `json:"reason"`
	Scope    string `json:"scope"`
	SourceIP string `json:"source_ip,omitempty"`
}
type LimitStatus struct {
	UserID  int    `json:"user_id"`
	Limited bool   `json:"limited"`
	Reason  string `json:"reason,omitempty"`
	Scope   string `json:"scope"`
}
type ActiveIP struct {
	UserID      int    `json:"user_id"`
	SourceIP    string `json:"source_ip"`
	Connections int    `json:"connections"`
}

func CanonicalIP(raw string) (string, error) {
	ip, e := netip.ParseAddr(raw)
	if e != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return "", errors.New("invalid source IP")
	}
	return ip.Unmap().String(), nil
}
func IPBlockKey(user int, ip string) string { return fmt.Sprintf("%d:%s", user, ip) }
func (r *Registry) blockedIP(user int, ip string, now time.Time) bool {
	return r.ipBlocks[IPBlockKey(user, ip)].Until.After(now) || r.ipBlocks[IPBlockKey(0, ip)].Until.After(now)
}
func (r *Registry) SetReportIPs(enabled bool) { r.mu.Lock(); r.reportIPs = enabled; r.mu.Unlock() }
func (r *Registry) RestoreIPBlocks(blocks map[string]protocol.IPBlock) {
	r.mu.Lock()
	r.ipBlocks = protocol.Clone(blocks)
	if r.ipBlocks == nil {
		r.ipBlocks = map[string]protocol.IPBlock{}
	}
	r.mu.Unlock()
}
func (r *Registry) SetIPBlock(key string, block protocol.IPBlock) {
	r.mu.Lock()
	if block.Until.IsZero() {
		delete(r.ipBlocks, key)
	} else {
		r.ipBlocks[key] = block
	}
	r.mu.Unlock()
}
func (r *Registry) ExpireIPBlocks(now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var expired []string
	for key, block := range r.ipBlocks {
		if !block.Until.After(now) {
			delete(r.ipBlocks, key)
			expired = append(expired, key)
		}
	}
	return expired
}
func (r *Registry) DropIP(ip string, user int) int {
	r.mu.RLock()
	var close []*Lease
	for _, l := range r.connections {
		if l.Info.SourceIP == ip && (user == 0 || l.Info.UserID == user) {
			close = append(close, l)
		}
	}
	r.mu.RUnlock()
	for _, l := range close {
		l.Close()
	}
	return len(close)
}
func (r *Registry) ActiveIPs(user int) []ActiveIP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []ActiveIP{}
	for id := range r.users {
		if user > 0 && id != user {
			continue
		}
		for ip, count := range r.activeIPs(id) {
			out = append(out, ActiveIP{UserID: id, SourceIP: ip, Connections: count})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserID != out[j].UserID {
			return out[i].UserID < out[j].UserID
		}
		return out[i].SourceIP < out[j].SourceIP
	})
	return out
}
