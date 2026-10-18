package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type sourceStage struct {
	stagedBans
	Sources  map[string]sourceState `json:"sources"`
	Remove   []string               `json:"remove"`
	Complete bool                   `json:"complete"`
}

func (g *Guard) syncSources(ctx context.Context, update protocol.FirewallUpdate) error {
	if err := validateUpdate(update); err != nil {
		return err
	}
	if !protocol.ValidName(update.SnapshotID) || update.Index < 0 || update.Index > 10000 {
		return errors.New("invalid source snapshot")
	}
	if g.sourceUpgradePending() {
		return errors.New("source synchronization awaits update confirmation")
	}
	g.sourceMu.Lock()
	defer g.sourceMu.Unlock()
	release, err := g.lockBulk(ctx)
	if err != nil {
		return err
	}
	defer release()
	g.mu.Lock()
	active := g.state.SourceMasterVersion
	policy := g.policy.Load()
	g.mu.Unlock()
	if update.Version < active {
		return nil
	}
	if policy == nil || !policy.Enabled {
		return errors.New("firewall policy is not active")
	}
	if err := os.MkdirAll(g.file("bulk"), 0700); err != nil {
		return err
	}
	var stage sourceStage
	if raw, err := os.ReadFile(g.file("source-sync.json")); err == nil {
		if json.Unmarshal(raw, &stage) != nil {
			return errors.New("invalid source staging metadata")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if stage.ID != update.SnapshotID {
		if update.Index != 0 {
			return errors.New("source snapshot must start at zero")
		}
		if err := g.clearSourceStage(); err != nil {
			return err
		}
		stage = sourceStage{stagedBans: stagedBans{ID: update.SnapshotID, Version: update.Version, SourcesOnly: true}, Sources: map[string]sourceState{}}
	}
	if stage.Version != update.Version || update.Index > stage.Next {
		return errors.New("source snapshot version or order differs")
	}
	if update.Index == stage.Next {
		for _, source := range update.Sources {
			if err := g.stageSource(ctx, &stage, source); err != nil {
				return err
			}
		}
		stage.Remove = append(stage.Remove, update.RemoveSources...)
		stage.Complete = stage.Complete || update.SourcesComplete
		stage.Next++
		raw, err := json.Marshal(stage)
		if err != nil {
			return err
		}
		if err = state.AtomicWrite(g.file("source-sync.json"), raw, 0600); err != nil {
			return err
		}
	}
	if !update.Final {
		return nil
	}
	if err := g.finishSourceFiles(ctx, &stage); err != nil {
		return err
	}
	g.mu.Lock()
	if update.Version < g.state.SourceMasterVersion {
		g.mu.Unlock()
		return nil
	}
	previous := g.state
	next := map[string]sourceState{}
	if !stage.Complete {
		for id, source := range g.state.Sources {
			next[id] = source
		}
	}
	for id, source := range stage.Sources {
		old := g.state.Sources[id]
		if old.Generation == source.Generation {
			source.Expired, source.BaseExpired = old.Expired, old.BaseExpired
			if source.Until.After(time.Now()) {
				source.Expired, source.BaseExpired = false, false
			}
			source.PreviousGeneration = old.PreviousGeneration
		} else {
			source.PreviousGeneration = old.Generation
		}
		next[id] = source
	}
	for _, id := range stage.Remove {
		delete(next, id)
	}
	g.state.Sources = next
	g.state.SourceMasterVersion = update.Version
	g.state.SourceRevision++
	g.state.Revision++
	if err := state.AtomicWrite(g.file("disk-sources-v1"), []byte("v1\n"), 0600); err != nil {
		g.state = previous
		g.mu.Unlock()
		return err
	}
	if err := g.compact(); err != nil {
		g.state = previous
		g.mu.Unlock()
		return err
	}
	g.dirty, g.sourcesDirty = true, true
	g.mu.Unlock()
	if err := g.clearSourceStage(); err != nil {
		return err
	}
	if err := g.cleanupSourceFiles(); err != nil {
		return err
	}
	release()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.enforce(ctx)
}
