package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"path/filepath"
)

func (g *Guard) stageSource(ctx context.Context, stage *sourceStage, source protocol.FirewallSource) error {
	if source.Reference {
		g.mu.Lock()
		old, exists := g.state.Sources[source.ID]
		g.mu.Unlock()
		if !exists || old.Generation != source.Generation {
			return errors.New("full source snapshot is required")
		}
		source.Reference = false
		source.Prefixes = nil
		old.FirewallSource = source
		stage.Sources[source.ID] = old
		return nil
	}
	old, exists := stage.Sources[source.ID]
	if exists && (old.Generation != source.Generation || !old.Until.Equal(source.Until)) {
		return errors.New("inconsistent source chunks")
	}
	if len(stage.Sources) >= 128 && !exists {
		return errors.New("source capacity exceeded")
	}
	path := sourcePath(g.dir, source.ID, source.Generation) + ".staging"
	if err := appendSourceRecords(ctx, g.dir, path, source.Prefixes); err != nil {
		return err
	}
	source.Prefixes = nil
	source.Reference = false
	old.FirewallSource = source
	stage.Sources[source.ID] = old
	return nil
}
func (g *Guard) finishSourceFiles(ctx context.Context, stage *sourceStage) error {
	for id, source := range stage.Sources {
		path := sourcePath(g.dir, id, source.Generation)
		if _, err := os.Stat(path + ".staging"); err == nil {
			if err = os.Remove(path + ".sorted"); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err = sortSourceRecords(ctx, g.dir, path+".staging", path+".sorted"); err != nil {
				return err
			}
			if err = publishRangeFile(path+".sorted", path); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		source.PrefixCount = int(info.Size() / rangeBytes)
		stage.Sources[id] = source
	}
	return nil
}
func (g *Guard) clearSourceStage() error {
	entries, err := os.ReadDir(g.file("bulk"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if !entry.IsDir() && (ext == ".staging" || ext == ".sorted" || len(entry.Name()) >= 5 && entry.Name()[:5] == "sort-") {
			if err = os.Remove(filepath.Join(g.file("bulk"), entry.Name())); err != nil {
				return err
			}
		}
	}
	if err = os.Remove(g.file("source-sync.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
