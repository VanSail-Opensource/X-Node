package firewall

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type automaticBackend interface {
	AutomaticExisting(context.Context) ([]protocol.FirewallExemption, error)
	Automatic(context.Context, []protocol.FirewallExemption) error
}

// GrantAutomatic changes only volatile exact-address protection. It neither
// removes durable bans nor modifies manual/paid grants or member admission.
func (g *Guard) GrantAutomatic(ctx context.Context, update protocol.AutomaticLeaseUpdate) (protocol.AutomaticLeaseAck, error) {
	ack := protocol.AutomaticLeaseAck{Epoch: update.Epoch}
	if err := update.Validate(time.Now()); err != nil {
		return ack, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	policy := g.policy.Load()
	if policy == nil || !policy.Enabled {
		return ack, errors.New("automatic leases await firewall activation")
	}
	g.manager.mu.Lock()
	defer g.manager.mu.Unlock()
	backend, ok := g.manager.backend().(automaticBackend)
	if !ok {
		return ack, errors.New("automatic lease backend unavailable")
	}
	release, err := g.manager.locked(ctx)
	if err != nil {
		return ack, err
	}
	defer release()
	if err := g.loadAutomaticLocked(ctx, backend); err != nil {
		return ack, err
	}
	next, err := g.automatic.stage(update, time.Now())
	if err != nil {
		return ack, err
	}
	items := automaticExemptions(next)
	if g.automatic.dirty {
		for ip, item := range g.automatic.entries {
			if _, replacing := next[ip]; !replacing {
				items = append(items, protocol.FirewallExemption{IP: ip.String(), Generation: "automatic", Until: item.deadline()})
			}
		}
	}
	if len(items) > 0 {
		if err := backend.Automatic(ctx, items); err != nil {
			return ack, err
		}
	}
	g.automatic.commit(next)
	g.automatic.dirty = false
	for _, grant := range update.Leases {
		ack.Generation = max(ack.Generation, grant.Generation)
	}
	return ack, nil
}

func (g *Guard) loadAutomaticLocked(ctx context.Context, backend automaticBackend) error {
	if g.automatic.loaded {
		return nil
	}
	items, err := backend.AutomaticExisting(ctx)
	if err != nil {
		return err
	}
	if len(items) > protocol.MaxAutomaticLeases {
		return errors.New("existing automatic lease capacity exceeded")
	}
	next := map[netip.Addr]automaticEntry{}
	for _, item := range items {
		ip, err := netip.ParseAddr(item.IP)
		if err != nil {
			return errors.New("invalid existing automatic lease")
		}
		if item.Until.After(time.Now()) {
			next[ip] = automaticEntry{ip: ip, prior: item.Until, index: -1}
		}
	}
	g.automatic.commit(next)
	g.automatic.loaded = true
	return nil
}

func automaticExemptions(items map[netip.Addr]automaticEntry) []protocol.FirewallExemption {
	result := make([]protocol.FirewallExemption, 0, len(items))
	for ip, item := range items {
		result = append(result, protocol.FirewallExemption{IP: ip.String(), Generation: "automatic", Until: item.deadline()})
	}
	return result
}

func (g *Guard) restoreAutomaticLocked(ctx context.Context) error {
	if !g.automatic.dirty || len(g.automatic.entries) == 0 {
		return nil
	}
	items := map[netip.Addr]automaticEntry{}
	for ip, item := range g.automatic.entries {
		items[ip] = *item
	}
	g.manager.mu.Lock()
	defer g.manager.mu.Unlock()
	backend, ok := g.manager.backend().(automaticBackend)
	if !ok {
		return errors.New("automatic lease backend unavailable")
	}
	release, err := g.manager.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := backend.Automatic(ctx, automaticExemptions(items)); err != nil {
		return err
	}
	g.automatic.dirty = false
	return nil
}
