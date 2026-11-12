package state

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
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

func TestStateRecoveryRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Open(dir)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO recovery evidence was accepted")
		}
	case <-time.After(time.Second):
		// Release a regressed blocking opener before failing the test.
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			writer.Close()
		}
		t.Fatal("state recovery waited for a FIFO writer")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("rejected FIFO evidence was replaced", err)
	}
}

func TestStateRecoveryRejectsSymlinkWithoutReadingOrChangingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "original.json")
	raw := []byte(`{"agent_id":"original","users":[]}`)
	if err := os.WriteFile(target, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(dir); err == nil || store != nil {
		t.Fatal("linked recovery evidence was accepted")
	}
	if retained, err := os.ReadFile(target); err != nil || string(retained) != string(raw) {
		t.Fatal("rejected symlink changed target evidence", err)
	}
}
