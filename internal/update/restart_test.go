package update

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type restartRunner struct {
	manager *Manager
	t       *testing.T
}

func (r restartRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.t.Helper()
	if !r.manager.mu.TryLock() {
		r.t.Fatal("restart submitted while update mutex is held")
	}
	r.manager.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	release, err := host.LockContext(ctx, filepath.Join(r.manager.Dir, "lock"))
	if err != nil {
		r.t.Fatalf("restart submitted while host lock is held: %v", err)
	}
	release()
	if name != "systemctl" || !slices.Equal(args, []string{"--no-block", "restart", "x-node.service"}) {
		r.t.Fatalf("restart waits for its own shutdown: %s %v", name, args)
	}
	if r.manager.Pending() {
		r.t.Fatal("rollback was not durable before restart")
	}
	if status, ok := r.manager.Status().(Transaction); !ok || status.Status != "rolled_back" {
		r.t.Fatal("status unavailable from restart callback")
	}
	return nil, nil
}

func TestTransactionLockHonorsCancellation(t *testing.T) {
	m := &Manager{Dir: t.TempDir()}
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := m.lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock = %v", err)
	}
}

func TestUpgradeObserversNeverWaitForInstaller(t *testing.T) {
	m := &Manager{Dir: t.TempDir()}
	if err := m.write(Transaction{Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		pending := m.Pending()
		status, ok := m.Status().(Transaction)
		done <- pending && ok && status.Status == "pending"
	}()
	select {
	case valid := <-done:
		m.mu.Unlock()
		if !valid {
			t.Fatal("lost pending transaction")
		}
	case <-time.After(time.Second):
		m.mu.Unlock()
		<-done
		t.Fatal("main-loop observer blocked behind installer")
	}
}

func TestRollbackPublishesBothBinariesBeforeAsynchronousRestart(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{Dir: filepath.Join(dir, "updates")}
	if err := os.MkdirAll(m.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	tx := Transaction{Status: "pending", NodePath: filepath.Join(dir, "x-node"), CLIPath: filepath.Join(dir, "xnodectl")}
	for _, target := range []string{tx.NodePath, tx.CLIPath} {
		if err := os.WriteFile(target+".old", []byte("previous binary"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.write(tx); err != nil {
		t.Fatal(err)
	}
	m.Runner = restartRunner{m, t}
	if err := m.RollbackPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{tx.NodePath, tx.CLIPath} {
		data, err := os.ReadFile(target)
		if err != nil || string(data) != "previous binary" {
			t.Fatal("previous agent/CLI pair not restored", err)
		}
	}
}
