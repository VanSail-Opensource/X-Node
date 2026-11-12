package geodata

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A killed downloader cannot run its defer. Only day-old private staging
// directories are eligible; serving and rollback generations have other names.
func pruneAbandonedStages(ctx context.Context, dir string, now time.Time) error {
	f, err := os.Open(dir)
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
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".assets-") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if now.Sub(info.ModTime()) < 24*time.Hour {
				continue
			}
			if err = os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
			removed++
			if removed == 64 {
				return nil
			}
		}
		if len(entries) == 0 {
			return nil
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
	return nil
}

// A failed candidate cannot accumulate another complete copy on each refresh.
// Agent native preparation serializes this with activation and validation.
func prunePrepared(dir, candidate string) error {
	active, err := resolveGeneration(dir)
	if err != nil {
		return err
	}
	previous, err := generationPointer(dir, "previous.json", "", true)
	if err != nil {
		return err
	}
	keep := map[string]bool{candidate: true, active: true, previous: true}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !generationName(entry.Name()) {
			continue
		}
		target := filepath.Join(dir, entry.Name())
		if keep[target] {
			continue
		}
		if filepath.Dir(target) != filepath.Clean(dir) {
			return errors.New("invalid geodata cleanup scope")
		}
		if err = os.RemoveAll(target); err != nil {
			return err
		}
	}
	return nil
}
