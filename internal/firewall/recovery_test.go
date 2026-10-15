package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExpiryAndWatchdogIdentity(t *testing.T) {
	m, f, _ := fixture(t)
	p := applyFixture(t, m)
	if err := m.RollbackID(context.Background(), "another"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.log(), "nft -f") {
		t.Fatal("stale watchdog restored newer transaction")
	}
	tx, err := readRecord(m.path())
	if err != nil {
		t.Fatal(err)
	}
	tx.Deadline = time.Now().Add(-time.Second)
	if err = writeRecord(m.path(), tx); err != nil {
		t.Fatal(err)
	}
	if err = m.Confirm(context.Background(), p.ID); err == nil {
		t.Fatal("expired transaction confirmed")
	}
	if !strings.Contains(f.log(), "rollback.nft") {
		t.Fatal("expiry did not restore snapshot")
	}
	before := f.log()
	if err = m.Confirm(context.Background(), p.ID); err == nil {
		t.Fatal("rolled-back transaction confirmed")
	}
	if f.log() != before {
		t.Fatal("late confirmation replayed obsolete snapshot")
	}
}

func TestBootFilesRecoveredAfterMigrationFailure(t *testing.T) {
	m, f, _ := fixture(t)
	if err := os.MkdirAll(filepath.Dir(m.unitPath()), 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{m.ConfigPath, m.unitPath()} {
		if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := applyFixture(t, m)
	f.fail = "systemctl enable"
	if err := m.Confirm(context.Background(), p.ID); err == nil {
		t.Fatal("failed persistence confirmed")
	}
	for _, path := range []string{m.ConfigPath, m.unitPath()} {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != "original" {
			t.Fatal("original file not recovered", path, err)
		}
	}
	if _, err := os.Stat(m.dropinPath()); !os.IsNotExist(err) {
		t.Fatal("new drop-in survived rollback")
	}
}

func TestRestoreLegacyPolicyAndPendingTransaction(t *testing.T) {
	m, f, b := fixture(t)
	p := applyFixture(t, m)
	if err := m.Confirm(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	confirmed, err := readRecord(filepath.Join(m.Dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	confirmed.Engine = 0
	confirmed.Status = "pending"
	confirmed.Redirect = true
	if err = writeRecord(filepath.Join(m.Dir, "policy.json"), confirmed); err != nil {
		t.Fatal(err)
	}
	// Legacy policy.json was written before its pending status was updated.
	if err = m.RestoreFile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.redirect {
		t.Fatal("boot enabled unprobed DNS")
	}
	if err = m.Migrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	migrated, err := readRecord(filepath.Join(m.Dir, "policy.json"))
	if err != nil || migrated.Engine != 1 || !migrated.Redirect {
		t.Fatal("legacy policy migration lost intent", err)
	}
	changed := policy()
	changed.UDPPorts = []int{443}
	if _, err = m.Apply(context.Background(), "unconfirmed", changed, false); err != nil {
		t.Fatal(err)
	}
	// Copy fields into a new manager; never copy a mutex already in use.
	restart := &Manager{Dir: m.Dir, ConfigPath: m.ConfigPath, UnitPath: m.UnitPath, Executable: m.Executable, Runner: f, Backend: b}
	if err = restart.RestoreFile(context.Background()); err != nil {
		t.Fatal(err)
	}
	tx, err := readRecord(m.path())
	if err != nil || tx.Status != "rolled_back" {
		t.Fatal("restart kept unconfirmed policy", err)
	}
}

func TestUpgradeDefersMigration(t *testing.T) {
	m, _, _ := fixture(t)
	p := applyFixture(t, m)
	dir := filepath.Join(filepath.Dir(m.Dir), "updates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "transaction.json"), []byte(`{"status":"pending"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(context.Background(), p.ID); err == nil {
		t.Fatal("unconfirmed binary migrated boot policy")
	}
	if _, err := os.Stat(m.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("boot config changed before binary confirmation")
	}
	if err := os.WriteFile(filepath.Join(dir, "transaction.json"), []byte(`{"status":"confirmed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDNSCannotRacePendingPolicy(t *testing.T) {
	m, _, b := fixture(t)
	p := applyFixture(t, m)
	if err := m.Confirm(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background(), "next", policy(), true); err != nil {
		t.Fatal(err)
	}
	if err := m.EnableConfirmedDNS(context.Background(), true); err == nil {
		t.Fatal("DNS changed pending policy")
	}
	if b.dns {
		t.Fatal("DNS backend was invoked")
	}
}

func TestWatchdogFailureDoesNotTouchKernel(t *testing.T) {
	m, f, b := fixture(t)
	f.fail = "systemd-run"
	if _, err := m.Apply(context.Background(), "request", policy(), false); err == nil {
		t.Fatal("watchdog failure ignored")
	}
	if b.calls != 0 {
		t.Fatal("kernel changed before watchdog was armed")
	}
}
