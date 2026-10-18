package geodata

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

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
