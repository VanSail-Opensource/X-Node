package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncompleteOriginalSnapshotCannotBecomeAnUninstallCheckpoint(t *testing.T) {
	m, runner, backend := fixture(t)
	runner.ruleset = ufwRuleset
	if err := os.MkdirAll(originalCompatPath(m.Dir), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background(), "first", policy(), false); err == nil {
		t.Fatal("incomplete original snapshot was accepted")
	}
	if backend.calls != 0 {
		t.Fatal("kernel changed before recovery dependencies were durable")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "original.nft")); !os.IsNotExist(err) {
		t.Fatal("incomplete snapshot published its first-prepare marker", err)
	}
	if err := os.Remove(originalCompatPath(m.Dir)); err != nil {
		t.Fatal(err)
	}
	pending, err := m.Apply(context.Background(), "retry", policy(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Confirm(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	if err = m.RestoreOriginal(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original-ip-filter.rules", "original-ip6-filter.rules"} {
		if !strings.Contains(runner.log(), "-restore "+filepath.Join(m.Dir, name)) {
			t.Fatal("retry lost original iptables recovery evidence", name)
		}
	}
}

func TestCorruptFirewallRecordsCannotPermitMutationOrLookUnmanaged(t *testing.T) {
	for _, malformed := range []string{"null", `{}`, `{"status":"future"}`, `{"status":"confirmed"}`, `{"status":"pending","status":"confirmed"}`, `{"id":"old","status":"confirmed","deadline":"2026-11-12T00:00:00Z","policy":null}`} {
		t.Run(malformed, func(t *testing.T) {
			m, runner, backend := fixture(t)
			if err := os.MkdirAll(m.Dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(m.path(), []byte(malformed), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Apply(context.Background(), "new", policy(), false); err == nil {
				t.Fatal("invalid recovery state permitted a new policy")
			}
			if err := m.RestoreFile(context.Background()); err == nil {
				t.Fatal("invalid transaction allowed boot restoration")
			}
			if err := m.Rollback(context.Background()); err == nil {
				t.Fatal("invalid transaction reported successful recovery")
			}
			status, ok := m.Status().(map[string]string)
			if !ok || status["status"] != "error" || backend.calls != 0 || runner.log() != "" {
				t.Fatal("corrupt state was not inert and unavailable", status)
			}
			if raw, err := os.ReadFile(m.path()); err != nil || string(raw) != malformed {
				t.Fatal("corrupt evidence changed", err)
			}
		})
	}
}

func TestInvalidUpgradeEvidenceFencesBothBootAndSourceMigrations(t *testing.T) {
	m, _, backend := fixture(t)
	pending := applyFixture(t, m)
	dir := filepath.Join(filepath.Dir(m.Dir), "updates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	guard := &Guard{dir: m.Dir}
	for _, malformed := range []string{"null", `{}`, `{"status":"future"}`, `{"status":"confirmed"}`} {
		if err := os.WriteFile(filepath.Join(dir, "transaction.json"), []byte(malformed), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.Confirm(context.Background(), pending.ID); err == nil {
			t.Fatal("invalid upgrade state authorized boot migration", malformed)
		}
		if !guard.sourceUpgradePending() {
			t.Fatal("invalid upgrade state authorized source-format migration", malformed)
		}
		if backend.calls != 1 {
			t.Fatal("invalid upgrade state changed the live firewall")
		}
	}
	if _, err := os.Stat(m.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("invalid upgrade state changed boot persistence", err)
	}
}
