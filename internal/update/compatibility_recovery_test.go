package update

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCompatibilityInspectionRejectsNullOrIncompletePersistedPolicy(t *testing.T) {
	for _, location := range []string{"state.json", "firewall/policy.json", "firewall/pending.json", "firewall/previous-policy.json", "firewall/candidate.json"} {
		for _, malformed := range []string{"null", `{}`} {
			t.Run(location+malformed, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, location)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(malformed), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := (&Manager{Dir: filepath.Join(dir, "updates")}).requiredCapabilities(); err == nil {
					t.Fatal("invalid policy evidence authorized a replacement binary")
				}
				if raw, err := os.ReadFile(path); err != nil || string(raw) != malformed {
					t.Fatal("compatibility inspection changed invalid evidence", err)
				}
			})
		}
	}
}

func TestEmptyOriginalXTablesManifestDoesNotInventAnUpgradeRequirement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firewall", "original-compat.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: filepath.Join(dir, "updates")}
	if err := os.WriteFile(path, []byte(`[]`), 0600); err != nil {
		t.Fatal(err)
	}
	required, err := m.requiredCapabilities()
	if err != nil || slices.Contains(required, "xtables_compat_snapshot_v1") {
		t.Fatal("empty compatibility manifest prevents a safe downgrade", required, err)
	}
	if err = os.WriteFile(path, []byte(`null`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.requiredCapabilities(); err == nil {
		t.Fatal("corrupt compatibility manifest became an empty snapshot")
	}
}
