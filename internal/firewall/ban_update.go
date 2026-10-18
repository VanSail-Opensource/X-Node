package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// Update commits an immediate master command. Absolute deadlines make retries
// independent of execution delay; a new command may deliberately shorten a ban.
func (g *Guard) Update(ctx context.Context, update protocol.FirewallUpdate) error {
	if update.SourcesOnly || len(update.Sources) > 0 {
		return errors.New("source inventories require staged synchronization")
	}
	if err := validateUpdate(update); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if update.Version < g.state.MasterVersion {
		return nil
	}
	if update.Version == g.state.MasterVersion {
		if g.dirty {
			return g.enforceMode(ctx, false)
		}
		return nil
	}
	if err := g.flushPending(); err != nil {
		return err
	}
	if policy := g.policy.Load(); policy == nil || !policy.Enabled {
		return errors.New("firewall policy is not active")
	}
	if err := state.AtomicWrite(g.file("controlled-v1"), []byte("v1\n"), 0600); err != nil {
		return err
	}
	record := journalRecord{MasterVersion: update.Version, SnapshotID: update.SnapshotID, Bans: update.Bans, Exemptions: update.Exemptions, RemoveExemptions: update.RemoveExemptions}
	for i := range record.Bans {
		prefix, _ := protocol.FirewallPrefix(record.Bans[i].Prefix)
		record.Bans[i].Prefix = prefix.String()
	}
	for i := range record.Exemptions {
		key, _ := protocol.ExemptionKey(record.Exemptions[i].IP)
		record.Exemptions[i].IP = key
	}
	for _, raw := range update.Remove {
		prefix, _ := protocol.FirewallPrefix(raw)
		record.Remove = append(record.Remove, prefix.String())
	}
	for i, raw := range record.RemoveExemptions {
		key, err := protocol.ExemptionKey(raw)
		if err != nil {
			return err
		}
		record.RemoveExemptions[i] = key
	}
	if err := g.markExemptionFormat(record.Exemptions); err != nil {
		return err
	}
	if err := g.appendJournal(record); err != nil {
		return err
	}
	return g.enforceMode(ctx, false)
}
