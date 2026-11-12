package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteReportsPublicationBeforeDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoint")
	if err := os.WriteFile(path, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected directory sync failure")
	published, err := atomicWriteWithDirectorySync(path, []byte("replacement"), 0600, func(got string) error {
		if got != dir {
			t.Fatalf("directory sync target = %q, want %q", got, dir)
		}
		return failure
	})
	if !published || !errors.Is(err, failure) {
		t.Fatal("post-rename failure lost publication status", published, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("injected failure did not occur after replacement", string(data), err)
	}
}

func TestAtomicWriteReportsNoPublicationWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoint")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(path, "operator-data")
	if err := os.WriteFile(original, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	synced := false
	published, err := atomicWriteWithDirectorySync(path, []byte("replacement"), 0600, func(string) error {
		synced = true
		return nil
	})
	if published || err == nil || synced {
		t.Fatal("failed rename reported publication or synced the replacement", published, synced, err)
	}
	data, err := os.ReadFile(original)
	if err != nil || string(data) != "retained" {
		t.Fatal("failed rename changed existing data", string(data), err)
	}
}
