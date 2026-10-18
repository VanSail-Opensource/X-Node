package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ufwRuleset mirrors the tables Ubuntu's UFW leaves behind: iptables-nft owns
// them and nft cannot parse their xtables compatibility expressions.
const ufwRuleset = `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy drop;
		meta l4proto ipv6-icmp xt match "icmp6" ip6 hoplimit 255 counter packets 0 bytes 0 accept
	}

	chain ufw-before-input {
	}
}

table ip6 filter {
	chain INPUT {
		type filter hook input priority filter; policy drop;
		meta l4proto ipv6-icmp xt match "icmp6" counter packets 0 bytes 0 accept
	}
}

table inet x_node {
	chain input {
		type filter hook input priority filter; policy drop;
		counter packets 0 bytes 0 accept
	}
}
`

func TestSplitCompatTablesSeparatesIptablesOwnership(t *testing.T) {
	native, tables, err := splitCompatTables([]byte(ufwRuleset))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(native), "xt match") || strings.Contains(string(native), "table ip filter") || strings.Contains(string(native), "table ip6 filter") {
		t.Fatal("iptables-owned tables remained in the nft snapshot", string(native))
	}
	if !strings.Contains(string(native), "table inet x_node") {
		t.Fatal("native tables were dropped from the snapshot")
	}
	if len(tables) != 2 || tables[0] != (compatTable{Family: "ip", Table: "filter"}) || tables[1] != (compatTable{Family: "ip6", Table: "filter"}) {
		t.Fatalf("unexpected compatibility tables: %#v", tables)
	}
}

func TestSplitCompatTablesDetectsOwnerMarkerWithoutExpressions(t *testing.T) {
	ruleset := "table ip nat { # progname iptables\n\tchain POSTROUTING {\n\t}\n}\ntable inet x_node {\n}\n"
	native, tables, err := splitCompatTables([]byte(ruleset))
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 1 || tables[0] != (compatTable{Family: "ip", Table: "nat"}) {
		t.Fatalf("owner marker ignored: %#v", tables)
	}
	if strings.Contains(string(native), "table ip nat") {
		t.Fatal("owner table remained in the nft snapshot")
	}
}

func TestSplitCompatTablesRejectsUnsupportedStates(t *testing.T) {
	if _, _, err := splitCompatTables([]byte("table ip filter {\n\tchain INPUT {\n")); err == nil {
		t.Fatal("unterminated snapshot accepted")
	}
	if _, _, err := splitCompatTables([]byte("table bridge filter {\n\tchain INPUT {\n\t\txt match \"physdev\" drop\n\t}\n}\n")); err == nil {
		t.Fatal("unsupported xtables family accepted")
	}
}

func TestRecoveryReplaysIptablesOwnedTables(t *testing.T) {
	m, f, _ := fixture(t)
	f.ruleset = ufwRuleset
	if _, err := m.Apply(context.Background(), "request", policy(), false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(filepath.Join(m.Dir, "rollback.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snapshot), "xt match") {
		t.Fatal("rollback snapshot cannot be replayed by nft")
	}
	for _, name := range []string{"rollback-ip-filter.rules", "rollback-ip6-filter.rules", "original-ip-filter.rules"} {
		if _, err := os.Stat(filepath.Join(m.Dir, name)); err != nil {
			t.Fatal("missing compatibility snapshot", name, err)
		}
	}
	if !strings.Contains(f.log(), "iptables-nft-save -t filter") || !strings.Contains(f.log(), "ip6tables-nft-save -t filter") {
		t.Fatal("iptables-owned tables were not saved by their front end")
	}
	if err := m.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	log := f.log()
	nft := strings.LastIndex(log, "nft -f "+filepath.Join(m.Dir, "rollback.nft"))
	v4 := strings.LastIndex(log, "iptables-nft-restore "+filepath.Join(m.Dir, "rollback-ip-filter.rules"))
	v6 := strings.LastIndex(log, "ip6tables-nft-restore "+filepath.Join(m.Dir, "rollback-ip6-filter.rules"))
	if nft < 0 || v4 < nft || v6 < v4 {
		t.Fatalf("compatibility tables were not replayed after the native snapshot:\n%s", log)
	}
}

func TestUninstallReplaysOriginalIptablesTables(t *testing.T) {
	m, f, _ := fixture(t)
	f.ruleset = ufwRuleset
	p := applyFixture(t, m)
	if err := m.Confirm(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.RestoreOriginal(context.Background()); err != nil {
		t.Fatal(err)
	}
	log := f.log()
	nft := strings.LastIndex(log, "nft -f "+filepath.Join(m.Dir, "original.nft"))
	v4 := strings.LastIndex(log, "iptables-nft-restore "+filepath.Join(m.Dir, "original-ip-filter.rules"))
	v6 := strings.LastIndex(log, "ip6tables-nft-restore "+filepath.Join(m.Dir, "original-ip6-filter.rules"))
	if nft < 0 || v4 < nft || v6 < v4 {
		t.Fatalf("original compatibility tables were not replayed:\n%s", log)
	}
}

func TestRestoreCompatRejectsUntrustedState(t *testing.T) {
	m, _, _ := fixture(t)
	for _, s := range []compatSnapshot{
		{Family: "ip", Table: "filter", Backup: filepath.Join(m.Dir, "rules"), Restore: "sh"},
		{Family: "ip", Table: "filter", Backup: "/etc/passwd", Restore: "iptables-restore"},
		{Family: "bridge", Table: "filter", Backup: filepath.Join(m.Dir, "rules"), Restore: "iptables-restore"},
	} {
		s.Backup = filepath.Clean(s.Backup)
		if err := m.restoreCompat(context.Background(), []compatSnapshot{s}); err == nil {
			t.Fatalf("untrusted compatibility state accepted: %#v", s)
		}
	}
}
