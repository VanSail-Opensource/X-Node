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
	if err := os.WriteFile(filepath.Join(fw, "original-services.json"), []byte(`{"services":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.checkCapabilities([]byte(`{"capabilities":["native_firewall_v1"]}`)); err == nil {
		t.Fatal("downgrade lost host service recovery")
	}
	if err := m.checkCapabilities([]byte(`{"capabilities":["native_firewall_v1","host_firewall_ownership_v1"]}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fw, "original-compat.json"), []byte(`[{"family":"ip","table":"filter","backup":"/var/lib/x-node/firewall/original-ip-filter.rules","restore":"iptables-nft-restore"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.checkCapabilities([]byte(`{"capabilities":["native_firewall_v1","host_firewall_ownership_v1"]}`)); err == nil {
		t.Fatal("downgrade lost xtables compatibility recovery")
	}
	if err := m.checkCapabilities([]byte(`{"capabilities":["native_firewall_v1","host_firewall_ownership_v1","xtables_compat_snapshot_v1"]}`)); err != nil {
		t.Fatal(err)
	}
}
