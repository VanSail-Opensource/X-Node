package geodata

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"net/http"
	"os"
	"path/filepath"
)

// Resolve preserves the read-only legacy fallback. Mutation and cleanup use
// resolveGeneration so uncertain recovery evidence cannot authorize deletion.
func Resolve(dir string) string {
	path, err := resolveGeneration(dir)
	if err != nil {
		return dir
	}
	return path
}

// Ensure preserves the public download-and-publish helper used by local utilities.
func Ensure(ctx context.Context, dir string, p Policy, hashes map[string]string, client *http.Client, refresh bool) error {
	target, err := Prepare(ctx, dir, p, hashes, client, refresh)
	if err != nil || len(p.Assets) == 0 {
		return err
	}
	return Activate(dir, target)
}

// Activate publishes a verified generation only after native activation succeeds.
func Activate(dir, target string) error {
	name := filepath.Base(target)
	if filepath.Clean(filepath.Dir(target)) != filepath.Clean(dir) || !generationName(name) {
		return errors.New("invalid asset generation")
	}
	previous, err := resolveGeneration(dir)
	if err != nil {
		return err
	}
	retained, err := generationPointer(dir, "previous.json", "", true)
	if err != nil {
		return err
	}
	if previous != target {
		raw, err := json.Marshal(map[string]string{"generation": filepath.Base(previous)})
		if err != nil {
			return err
		}
		if err = state.AtomicWrite(filepath.Join(dir, "previous.json"), raw, 0600); err != nil {
			return err
		}
	} else if retained != "" {
		previous = retained
	}
	raw, err := json.Marshal(map[string]string{"generation": name})
	if err != nil {
		return err
	}
	if err = state.AtomicWrite(filepath.Join(dir, "active.json"), raw, 0600); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !generationName(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if path != target && path != previous {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	return nil
}
