package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func transactionFixture(dir string) Transaction {
	return Transaction{ID: "upgrade", Version: "v2.0.11", Previous: "v2.0.10", Status: "pending", Deadline: time.Now().UTC().Add(time.Minute), NodePath: filepath.Join(dir, "x-node"), CLIPath: filepath.Join(dir, "xnodectl")}
}

func TestMalformedTransactionCannotBecomeIdleOrAuthorizeCleanup(t *testing.T) {
	for _, malformed := range []string{"null", `{}`, `{"status":"confirmed"}`, `{"status":"future"}`, `[]`} {
		t.Run(malformed, func(t *testing.T) {
			dir := t.TempDir()
			m := New(filepath.Join(dir, "updates"), "v2.0.11", nil)
			m.NodePath, m.CLIPath = filepath.Join(dir, "x-node"), filepath.Join(dir, "xnodectl")
			if err := os.Mkdir(m.Dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.Dir, "transaction.json")
			if err := os.WriteFile(path, []byte(malformed), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(m.NodePath+".new", []byte("staged evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			status, ok := m.Status().(map[string]string)
			if !m.Pending() || !ok || status["status"] != "unavailable" {
				t.Error("malformed recovery state appeared usable", status)
			}
			if err := m.Confirm(context.Background()); err == nil {
				t.Error("malformed recovery state authorized confirmation/cleanup")
			}
			if raw, err := os.ReadFile(m.NodePath + ".new"); err != nil || string(raw) != "staged evidence" {
				t.Error("uncertain transaction lost staged evidence", err)
			}
			if raw, err := os.ReadFile(path); err != nil || string(raw) != malformed {
				t.Fatal("invalid transaction was rewritten", err)
			}
		})
	}
}

func TestTransactionReaderRejectsAmbiguousFieldsAndUnsafeTargets(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{Dir: dir}
	valid := transactionFixture(dir)
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		strings.Replace(string(raw), `"status":"pending"`, `"status":"pending","status":"confirmed"`, 1),
		strings.Replace(string(raw), `"status":"pending"`, `"Status":"confirmed"`, 1),
		strings.Replace(string(raw), `"pending"`, `"future"`, 1),
		strings.Replace(string(raw), `"unit":""`, `"unit":"--root=/other"`, 1),
		strings.Replace(string(raw), valid.NodePath, "relative-agent", 1),
		strings.Replace(string(raw), valid.CLIPath, valid.NodePath, 1),
	} {
		if err = os.WriteFile(filepath.Join(dir, "transaction.json"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = m.read(); err == nil {
			t.Fatal("ambiguous or unsafe recovery transaction accepted", value)
		}
	}
	for _, status := range []string{"pending", "confirmed", "rolled_back", "failed"} {
		valid.Status = status
		if err = m.write(valid); err != nil {
			t.Fatal(err)
		}
		if pending, err := PendingTransaction(dir); err != nil || pending != (status == "pending") {
			t.Fatal("valid transaction lost its migration fence", status, pending, err)
		}
	}
}

func TestTransactionInspectionBoundsRecoveryFilesWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"oversized", "fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "transaction.json")
			switch kind {
			case "oversized":
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(maxTransactionBytes + 1)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "missing"), path); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { _, err := readTransaction(path); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid recovery file accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("recovery inspection blocked on a nonregular file")
			}
		})
	}
}
