package firewall

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestIdenticalFirewallKeepsDurableTransactionIdentity(t *testing.T) {
	dir := t.TempDir()
	policy := protocol.FirewallPolicy{Enabled: true}
	m := &Manager{Dir: dir}
	tx := record{Pending: Pending{ID: "original", Status: "pending", Policy: policy, Deadline: time.Now().Add(time.Minute)}, Engine: 1, Ownership: true}
	if err := writeRecord(m.path(), tx); err != nil {
		t.Fatal(err)
	}
	p, reused, err := m.Reuse(context.Background(), policy, false)
	if err != nil || !reused || p.ID != "original" {
		t.Fatal("pending transaction not reused", err)
	}
	changed := policy
	changed.Protect = true
	if _, reused, err = m.Reuse(context.Background(), changed, false); err != nil || reused {
		t.Fatal("changed policy reused", err)
	}
	tx.Status = "confirmed"
	if err = writeRecord(m.path(), tx); err != nil {
		t.Fatal(err)
	}
	if err = writeRecord(filepath.Join(dir, "policy.json"), tx); err != nil {
		t.Fatal(err)
	}
	if _, reused, err = m.Reuse(context.Background(), policy, false); err != nil || !reused {
		t.Fatal("confirmed ownership not reused", err)
	}
	tx.Status = "pending"
	tx.Deadline = time.Now().Add(-time.Second)
	if err = writeRecord(m.path(), tx); err != nil {
		t.Fatal(err)
	}
	if _, reused, err = m.Reuse(context.Background(), policy, false); err != nil || reused {
		t.Fatal("expired transaction skipped recovery", err)
	}
}
