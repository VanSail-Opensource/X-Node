package firewall

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// ProtectNodes replaces volatile managed-node exclusions. These observations
// never enter snapshots, command history, or the durable firewall journal.
func (g *Guard) ProtectNodes(ctx context.Context, ips []string) error {
	if len(ips) > 100000 {
		return errors.New("node exclusion snapshot exceeds bound")
	}
	next := map[string]bool{}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if prefix, e := netip.ParsePrefix(address.String()); e == nil {
			ip := prefix.Addr().Unmap()
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				next[ip.String()] = true
			}
		}
	}
	for _, raw := range ips {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return errors.New("invalid node exclusion address")
		}
		next[ip.Unmap().String()] = true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodeIPs = next
	return g.applyProtectedLocked(ctx)
}

// ApplyUserProtection runs before the configuration is acknowledged. Admission
// and kernel exemption state therefore share one successful deployment boundary.
func (g *Guard) ApplyUserProtection(ctx context.Context, users []protocol.User) error {
	next := map[string]time.Time{}
	for _, user := range users {
		if !user.WhitelistEnabled || len(user.InboundTags) == 0 {
			continue
		}
		until := time.Now().Add(365 * 24 * time.Hour)
		if user.ValidUntil != nil {
			until = *user.ValidUntil
		}
		for _, ip := range user.WhitelistedIPs {
			if until.After(next[ip]) {
				next[ip] = until
			}
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.memberIPs = next
	if g.nodeIPs == nil {
		g.nodeIPs = map[string]bool{}
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			if prefix, e := netip.ParsePrefix(address.String()); e == nil {
				ip := prefix.Addr().Unmap()
				if ip.IsGlobalUnicast() && !ip.IsPrivate() {
					g.nodeIPs[ip.String()] = true
				}
			}
		}
	}
	return g.applyProtectedLocked(ctx)
}

type protectedBackend interface {
	Protected(context.Context, []protocol.FirewallExemption) error
}

func (g *Guard) applyProtectedLocked(ctx context.Context) error {
	policy := g.policy.Load()
	if policy == nil || !policy.Enabled {
		return nil
	}
	deadlines := map[string]time.Time{}
	for ip, until := range g.memberIPs {
		deadlines[ip] = until
	}
	for ip := range g.nodeIPs {
		deadlines[ip] = time.Now().Add(365 * 24 * time.Hour)
	}
	items := make([]protocol.FirewallExemption, 0, len(deadlines))
	for ip, until := range deadlines {
		if until.After(time.Now()) {
			items = append(items, protocol.FirewallExemption{IP: ip, Generation: "managed", Until: until})
		}
	}
	g.manager.mu.Lock()
	defer g.manager.mu.Unlock()
	backend, ok := g.manager.backend().(protectedBackend)
	if !ok {
		if len(items) == 0 {
			return nil
		}
		return errors.New("protected source backend unavailable")
	}
	release, err := g.manager.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	return backend.Protected(ctx, items)
}
