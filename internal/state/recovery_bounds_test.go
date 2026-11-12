package state

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOversizedStateRecoveryRejectsBeforeAllocatingContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxStoreBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	store, err := Open(dir)
	runtime.ReadMemStats(&after)
	if err == nil || store != nil {
		t.Fatal("oversized recovery evidence was accepted")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= MaxStoreBytes {
		t.Fatalf("read oversized evidence before checking its size: allocated %d bytes", allocated)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != MaxStoreBytes+1 {
		t.Fatal("failed recovery modified original evidence", err)
	}
}

func TestStateRecoveryRejectsDirectoryWithoutReplacingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(dir); err == nil || store != nil {
		t.Fatal("non-file state was accepted")
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatal("invalid state path was replaced", err)
	}
}
