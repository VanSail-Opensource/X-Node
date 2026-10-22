package protocol

import (
	"errors"
	"net/netip"
	"time"
)

// MaxFirewallEventsPerFrame bounds durable event batches shared by masters and agents.
const MaxFirewallEventsPerFrame = 256

var FirewallRuleNames = []string{"closed_port", "invalid_packet", "syn_flood", "icmp_probe", "xray_tcp_probe", "xray_invalid", "xray_auth_failure", "source_match"}

type FirewallRule struct {
	Enabled       bool `json:"enabled"`
	Threshold     int  `json:"threshold"`
	WindowSeconds int  `json:"window_seconds"`
}

func (p FirewallPolicy) Rule(name string) (FirewallRule, bool) {
	if !p.Enabled {
		return FirewallRule{}, false
	}
	known := false
	for _, id := range FirewallRuleNames {
		if id == name {
			known = true
			break
		}
	}
	if !known {
		return FirewallRule{}, false
	}
	rule, ok := p.Rules[name]
	if !ok {
		rule = FirewallRule{Enabled: true, Threshold: 3, WindowSeconds: 86400}
	}
	return rule, rule.Enabled
}
func (p FirewallPolicy) BanDuration() time.Duration {
	if p.BanSeconds == 0 {
		return 72 * time.Hour
	}
	return time.Duration(p.BanSeconds) * time.Second
}

// FirewallBan is an authoritative operational restriction, distinct from user
// session IP controls and transient detector observations.
type FirewallBan struct {
	Prefix         string    `json:"prefix"`
	Generation     string    `json:"generation"`
	Until          time.Time `json:"until"`
	RefreshSeconds int       `json:"refresh_seconds"`
	Source         string    `json:"source,omitempty"`
}
type FirewallExemption struct {
	IP         string    `json:"ip"`
	Generation string    `json:"generation"`
	Until      time.Time `json:"until"`
}
type FirewallSource struct {
	Reference      bool      `json:"reference,omitempty"`
	ID             string    `json:"id"`
	Generation     string    `json:"generation"`
	Until          time.Time `json:"until"`
	RefreshSeconds int       `json:"refresh_seconds"`
	Prefixes       []string  `json:"prefixes"`
}
type FirewallEvent struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	IP         string    `json:"ip"`
	Prefix     string    `json:"prefix,omitempty"`
	Generation string    `json:"generation,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	Count      uint64    `json:"count"`
	FirstSeen  time.Time `json:"first_seen"`
	Time       time.Time `json:"time"`
}
type FirewallEvents struct {
	State       *FirewallState  `json:"state,omitempty"`
	InstanceID  string          `json:"instance_id"`
	KernelReady bool            `json:"kernel_ready"`
	Events      []FirewallEvent `json:"events"`
	Dropped     uint64          `json:"dropped"`
}
type FirewallEventAck struct {
	IDs []string `json:"ids"`
}

// Snapshot chunks stage outside the active ruleset until the final chunk is
// durable. A repeated generation preserves locally extended expiration times.
type FirewallUpdate struct {
	SourcesOnly      bool                `json:"sources_only,omitempty"`
	Version          uint64              `json:"version"`
	SourcesComplete  bool                `json:"sources_complete,omitempty"`
	RemoveSources    []string            `json:"remove_sources,omitempty"`
	SnapshotID       string              `json:"snapshot_id,omitempty"`
	Index            int                 `json:"index,omitempty"`
	Final            bool                `json:"final,omitempty"`
	Bans             []FirewallBan       `json:"bans,omitempty"`
	Exemptions       []FirewallExemption `json:"exemptions,omitempty"`
	Sources          []FirewallSource    `json:"sources,omitempty"`
	Remove           []string            `json:"remove,omitempty"`
	RemoveExemptions []string            `json:"remove_exemptions,omitempty"`
}

func FirewallPrefix(raw string) (netip.Prefix, error) {
	if ip, err := netip.ParseAddr(raw); err == nil {
		ip = ip.Unmap()
		bits := ip.BitLen()
		if ip.Is6() {
			bits = 64
		}
		return netip.PrefixFrom(ip, bits).Masked(), nil
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("invalid firewall prefix")
	}
	return p.Masked(), nil
}

func (p FirewallPolicy) ValidateDetection() error {
	if p.BanSeconds < 0 || p.BanSeconds > 31536000 {
		return errors.New("invalid firewall ban duration")
	}
	for name, rule := range p.Rules {
		known := false
		for _, id := range FirewallRuleNames {
			if name == id {
				known = true
			}
		}
		if !known || rule.Threshold < 1 || rule.Threshold > 1000000 || rule.WindowSeconds < 1 || rule.WindowSeconds > 31536000 {
			return errors.New("invalid firewall detection rule")
		}
	}
	return nil
}

func (b FirewallBan) Validate() error {
	prefix, err := FirewallPrefix(b.Prefix)
	if err != nil {
		return err
	}
	if prefix.Addr().Is4() && prefix.Bits() != 32 || prefix.Addr().Is6() && prefix.Bits() != 64 {
		return errors.New("individual bans require IPv4 addresses or IPv6 /64 prefixes")
	}
	if !ValidName(b.Generation) || b.Until.IsZero() || b.RefreshSeconds < 1 || b.RefreshSeconds > 31536000 || len(b.Source) > 128 {
		return errors.New("invalid firewall ban")
	}
	return nil
}
func (e FirewallExemption) Validate() error {
	prefix, err := ExemptionPrefix(e.IP)
	ip := prefix.Addr()
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || !ValidName(e.Generation) || e.Until.IsZero() {
		return errors.New("invalid firewall exemption")
	}
	return nil
}
