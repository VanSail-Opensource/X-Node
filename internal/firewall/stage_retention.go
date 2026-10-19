package firewall

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Called under sourceMu and the bulk host lock. Neither committed ranges nor
// rollback dependencies match these names. Recent partial transfers can resume.
func (g *Guard) pruneAbandonedStages(ctx context.Context, now time.Time) error {
	if g.sourceUpgradePending() {
		return nil
	}
	g.mu.Lock()
	retain := g.retainBulk
	g.mu.Unlock()
	if retain {
		return nil
	}
	sourceFresh, err := g.retainStage("source-sync.json", now)
	if err != nil {
		return err
	}
	countryFresh, err := g.retainStage("geoip-sync.json", now)
	if err != nil {
		return err
	}
	g.mu.Lock()
	dynamicFresh, err := g.retainStage("sync.json", now)
	if err == nil && !dynamicFresh {
		err = os.Remove(g.file("sync.json.gz"))
		if os.IsNotExist(err) {
			err = nil
		}
	}
	g.mu.Unlock()
	if err != nil {
		return err
	}
	f, err := os.Open(g.file("bulk"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	removed := 0
	for removed < 64 {
		entries, readErr := f.ReadDir(64)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if sourceFresh && (strings.HasSuffix(name, ".staging") || strings.HasSuffix(name, ".sorted")) || countryFresh && (strings.HasSuffix(name, ".country") || strings.HasSuffix(name, ".country-sorted")) {
				continue
			}
			disposable := strings.HasSuffix(name, ".staging") || strings.HasSuffix(name, ".sorted") || strings.HasSuffix(name, ".country") || strings.HasSuffix(name, ".country-sorted") || strings.HasPrefix(name, "sort-") || strings.HasPrefix(name, "migration-")
			if entry.IsDir() || !disposable {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if now.Sub(info.ModTime()) < 24*time.Hour {
				continue
			}
			if err = os.Remove(filepath.Join(g.file("bulk"), name)); err != nil {
				return err
			}
			removed++
			if removed == 64 {
				return nil
			}
		}
		if len(entries) == 0 || errors.Is(readErr, io.EOF) {
			return nil
		}
	}
	return nil
}

// Remove the stale cursor before its data, so an interrupted transfer must
// restart at chunk zero instead of publishing only its remaining chunks.
func (g *Guard) retainStage(name string, now time.Time) (bool, error) {
	info, err := os.Stat(g.file(name))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if now.Sub(info.ModTime()) < 24*time.Hour {
		return true, nil
	}
	return false, os.Remove(g.file(name))
}
