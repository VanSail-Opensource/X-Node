package geodata

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"net/http"
	"os"
	"path/filepath"
)

// Resolve returns one immutable verified domain-asset generation.
func Resolve(dir string) string {
	b, e := os.ReadFile(filepath.Join(dir, "active.json"))
	if e != nil {
		return dir
	}
	var data struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(b, &data) != nil || len(data.Generation) != 64 {
		return dir
	}
	if _, e = hex.DecodeString(data.Generation); e != nil {
		return dir
	}
	return filepath.Join(dir, data.Generation)
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
	if filepath.Clean(filepath.Dir(target)) != filepath.Clean(dir) || len(name) != 64 {
		return errors.New("invalid asset generation")
	}
	if _, err := hex.DecodeString(name); err != nil {
		return err
	}
	previous := Resolve(dir)
	if previous != target {
		raw, err := json.Marshal(map[string]string{"generation": filepath.Base(previous)})
		if err != nil {
			return err
		}
		if err = state.AtomicWrite(filepath.Join(dir, "previous.json"), raw, 0600); err != nil {
			return err
		}
	} else if raw, err := os.ReadFile(filepath.Join(dir, "previous.json")); err == nil {
		var pointer struct {
			Generation string `json:"generation"`
		}
		if json.Unmarshal(raw, &pointer) == nil && len(pointer.Generation) == 64 {
			if _, err := hex.DecodeString(pointer.Generation); err == nil {
				previous = filepath.Join(dir, pointer.Generation)
			}
		}
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
		if !entry.IsDir() || len(entry.Name()) != 64 {
			continue
		}
		if _, err := hex.DecodeString(entry.Name()); err != nil {
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
