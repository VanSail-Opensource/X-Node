package geodata

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// AdoptPrepared publishes an already downloaded private generation into the
// serving asset directory. The caller serializes this short step with native
// activation; the preceding network transfer need not hold that lock.
// Prepare supplied the verified content-derived name and synced asset files.
func AdoptPrepared(dir, prepared string) (string, error) {
	name := filepath.Base(prepared)
	info, err := os.Lstat(prepared)
	if err != nil {
		return "", err
	}
	if !generationName(name) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("invalid prepared asset generation")
	}
	// Check recovery references before publishing or retiring any generation.
	if _, err := resolveGeneration(dir); err != nil {
		return "", err
	}
	if _, err := generationPointer(dir, "previous.json", "", true); err != nil {
		return "", err
	}
	target := filepath.Join(dir, name)
	if existing, err := os.Lstat(target); os.IsNotExist(err) {
		if err := state.SyncDirectory(prepared); err != nil {
			return "", err
		}
		if err := os.Rename(prepared, target); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	} else if !existing.IsDir() || existing.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("invalid existing asset generation")
	}
	if err := state.SyncDirectory(dir); err != nil {
		return "", err
	}
	if err := prunePrepared(dir, target); err != nil {
		return "", err
	}
	return target, nil
}
