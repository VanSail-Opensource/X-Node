package geodata

import (
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func generationName(name string) bool {
	if len(name) != 64 {
		return false
	}
	_, err := hex.DecodeString(name)
	return err == nil
}

func generationPointer(dir, filename, missing string, legacyFlat bool) (string, error) {
	raw, err := state.ReadRecoveryFile(filepath.Join(dir, filename), 16<<10)
	if os.IsNotExist(err) {
		return missing, nil
	}
	if err != nil {
		return "", err
	}
	var pointer struct {
		Generation *string `json:"generation"`
	}
	if jsonv2.Unmarshal(raw, &pointer, jsonv2.RejectUnknownMembers(true)) != nil || pointer.Generation == nil {
		return "", errors.New("invalid asset generation pointer")
	}
	name := *pointer.Generation
	// The first historical activation records the previous flat asset directory
	// by basename. It is a compatibility sentinel, never a caller-selected path.
	if legacyFlat && name == filepath.Base(filepath.Clean(dir)) {
		return dir, nil
	}
	if !generationName(name) {
		return "", errors.New("invalid asset generation pointer")
	}
	return filepath.Join(dir, name), nil
}

func resolveGeneration(dir string) (string, error) {
	return generationPointer(dir, "active.json", dir, false)
}
