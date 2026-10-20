package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type banBackend interface {
	Bans(context.Context, []protocol.FirewallBan, []protocol.FirewallExemption, []protocol.FirewallSource, bool) error
}

func (g *Guard) enforce(ctx context.Context) error { return g.enforceMode(ctx, true) }
func (g *Guard) enforceMode(ctx context.Context, withSources bool) (result error) {
	defer func() { g.enforcementResult(result, time.Now()) }()
	policy := g.policy.Load()
	if policy == nil || !policy.Enabled {
		g.dirty = false
		g.sourcesDirty = false
		return nil
	}
	bans := []protocol.FirewallBan{}
	exemptions := []protocol.FirewallExemption{}
	sources := []protocol.FirewallSource{}
	now := time.Now()
	for _, ban := range g.state.Bans {
		if ban.Until.After(now) {
			bans = append(bans, ban)
		}
	}
	var dropped uint64
	bans, dropped = boundedBans(bans, banSetSize)
	g.dropped.Add(dropped)
	for _, exemption := range g.state.Exemptions {
		if exemption.Until.After(now) {
			exemptions = append(exemptions, exemption)
		}
	}
	if withSources && g.sourcesDirty {
		for _, source := range g.state.Sources {
			if source.Until.After(now) && !source.Expired {
				sources = append(sources, source.FirewallSource)
			}
		}
	}
	version, sourceVersion, replaceSources := g.state.Revision, g.state.SourceRevision, withSources && g.sourcesDirty
	g.mu.Unlock()
	err := g.manager.updateBans(ctx, version, sourceVersion, bans, exemptions, sources, replaceSources)
	g.mu.Lock()
	if err != nil {
		return err
	}
	if g.state.Revision == version && g.policy.Load() == policy {
		g.dirty = false
	}
	if replaceSources && g.state.SourceRevision == sourceVersion && g.policy.Load() == policy {
		g.sourcesDirty = false
	}
	return nil
}

type stagedBanBackend interface {
	StageSources(context.Context, []protocol.FirewallSource) (map[string]string, error)
	ApplyBans(context.Context, []protocol.FirewallBan, []protocol.FirewallExemption, map[string]string, bool, bool) error
}

func (m *Manager) updateBans(ctx context.Context, version, sourceVersion uint64, bans []protocol.FirewallBan, exemptions []protocol.FirewallExemption, sources []protocol.FirewallSource, replaceSources bool) error {
	bans, _ = boundedBans(bans, banSetSize)
	backend := m.backend()
	staged, canStage := backend.(stagedBanBackend)
	var targets map[string]string
	if canStage && replaceSources {
		if err := os.MkdirAll(m.Dir, 0700); err != nil {
			return err
		}
		release, err := lockContext(ctx, filepath.Join(m.Dir, "sources.lock"))
		if err != nil {
			return err
		}
		defer release()
		targets, err = staged.StageSources(ctx, sources)
		if err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	applyBans, applySources := version >= m.banVersion, replaceSources && sourceVersion >= m.sourceVersion
	if !applyBans && !applySources {
		return nil
	}
	release, err := m.locked(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err = m.ensureConfirmed(ctx); err != nil {
		return err
	}
	if canStage {
		err = staged.ApplyBans(ctx, bans, exemptions, targets, applyBans, applySources)
	} else {
		plain, ok := backend.(banBackend)
		if !ok {
			return errors.New("native firewall ban backend unavailable")
		}
		err = plain.Bans(ctx, bans, exemptions, sources, applySources)
	}
	if err != nil {
		return err
	}
	if applyBans {
		m.banVersion = version
	}
	if applySources {
		m.sourceVersion = sourceVersion
	}
	return nil
}

func (m *Manager) restoreBans(ctx context.Context, policy protocol.FirewallPolicy) error {
	if !policy.Enabled {
		return nil
	}
	backend, ok := m.backend().(banBackend)
	if !ok {
		return nil
	}
	guard, err := OpenGuard(m.Dir, m)
	if err != nil {
		return err
	}
	bans := []protocol.FirewallBan{}
	exemptions := []protocol.FirewallExemption{}
	sources := []protocol.FirewallSource{}
	now := time.Now()
	for _, ban := range guard.state.Bans {
		if ban.Until.After(now) {
			bans = append(bans, ban)
		}
	}
	for _, exemption := range guard.state.Exemptions {
		if exemption.Until.After(now) {
			exemptions = append(exemptions, exemption)
		}
	}
	for _, source := range guard.state.Sources {
		if source.Until.After(now) && !source.Expired {
			sources = append(sources, source.FirewallSource)
		}
	}
	_ = backend
	bans, _ = boundedBans(bans, banSetSize)
	return m.updateBans(ctx, guard.state.Revision, guard.state.SourceRevision, bans, exemptions, sources, true)
}
