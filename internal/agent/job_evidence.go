package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// The primary remains in place until its compact replacement is atomic. An
// evidence filename derived from content also prevents duplicate restart copies.
func (j *Jobs) preserveEvidence(source *os.File, original os.FileInfo, digest []byte) error {
	current, err := source.Stat()
	if err != nil || !os.SameFile(current, original) || current.Size() != original.Size() || !current.ModTime().Equal(original.ModTime()) {
		return errLegacyJobMetadata
	}
	target := j.path + ".legacy-" + hex.EncodeToString(digest)
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != original.Size() {
			return errLegacyJobMetadata
		}
		file, err := os.Open(target)
		if err != nil {
			return err
		}
		defer file.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, io.LimitReader(file, legacyJobRecoveryMaxBytes+1)); err != nil {
			return err
		}
		if !bytes.Equal(hash.Sum(nil), digest) {
			return errLegacyJobMetadata
		}
		return syncJobDirectory(filepath.Dir(j.path))
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(j.path), ".jobs-evidence-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(source, legacyJobRecoveryMaxBytes+1))
	if err == nil && (count != original.Size() || !bytes.Equal(hash.Sum(nil), digest)) {
		err = errLegacyJobMetadata
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncJobDirectory(filepath.Dir(j.path))
}

func syncJobDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("job evidence directory sync failed")
	}
	return nil
}

// AtomicWrite checks the file barrier but ignores directory sync failures.
// Durable job admission requires that additional barrier before native work.
func writeJobFile(path string, data []byte, mode os.FileMode) error {
	if err := state.AtomicWrite(path, data, mode); err != nil {
		return err
	}
	return syncJobDirectory(filepath.Dir(path))
}
