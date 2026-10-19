package geodata

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
	keep := map[string]bool{candidate: true, Resolve(dir): true}
	var previous struct {
		Generation string `json:"generation"`
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "previous.json")); err == nil && json.Unmarshal(raw, &previous) == nil && len(previous.Generation) == 64 {
		if _, err = hex.DecodeString(previous.Generation); err == nil {
			keep[filepath.Join(dir, previous.Generation)] = true
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 64 {
			continue
		}
		if _, err := hex.DecodeString(entry.Name()); err != nil {
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
