package hourly

import (
	"io"
	"os"
	"path/filepath"
)

const creditJournalMaxBytes = 2 << 20

func prepareCreditDirectory(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ErrCreditDurability
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ErrCreditDurability
	}
	// MkdirAll may have created several private ancestors. Flush each link so
	// losing a directory entry cannot erase issued obligations after a crash.
	for current := dir; ; current = filepath.Dir(current) {
		if err := syncCreditDirectory(current); err != nil {
			return err
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func readCreditFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > creditJournalMaxBytes {
		return nil, ErrCreditCorrupt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrCreditDurability
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrCreditCorrupt
	}
	raw, err := io.ReadAll(io.LimitReader(file, creditJournalMaxBytes+1))
	if err != nil {
		return nil, ErrCreditDurability
	}
	after, err := file.Stat()
	if err != nil || int64(len(raw)) != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, ErrCreditCorrupt
	}
	return raw, nil
}

// Do not use state.AtomicWrite: its parent-directory barrier is unchecked.
func writeCreditFile(path string, raw []byte) error {
	if len(raw) > creditJournalMaxBytes {
		return ErrCreditCapacity
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".hourly-credit-*")
	if err != nil {
		return ErrCreditDurability
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0600); err == nil {
		var n int
		n, err = file.Write(raw)
		if err == nil && n != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrCreditDurability
	}
	if err = os.Rename(temporary, path); err != nil {
		return ErrCreditDurability
	}
	return syncCreditDirectory(filepath.Dir(path))
}

func syncCreditDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrCreditDurability
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return ErrCreditDurability
	}
	return nil
}
