package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeFirewallPreventsUnsafeBinaryDowngrade(t *testing.T) {
	dir := t.TempDir()
	fw := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fw, 0700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: filepath.Join(dir, "updates")}
	if err := os.WriteFile(filepath.Join(fw, "policy.json"), []byte(`{"engine":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.checkCapabilities([]byte(`{"capabilities":[]}`)); err == nil {
		t.Fatal("incompatible boot engine accepted")
	}
	if err := m.checkCapabilities([]byte(`{"capabilities":["native_firewall_v1"]}`)); err != nil {
		t.Fatal(err)
	}
}
