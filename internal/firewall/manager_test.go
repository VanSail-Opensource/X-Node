package firewall

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls     []string
	failApply bool
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if name == "sshd" {
		return []byte("port 2222\n"), nil
	}
	if name == "nft" && len(args) > 0 && args[0] == "list" {
		return []byte("table inet old { }\n"), nil
	}
	if f.failApply && name == "nft" && len(args) > 1 && args[0] == "-f" && strings.Contains(args[1], "candidate") {
		return nil, errors.New("rejected")
	}
	return nil, nil
}
func TestRenderOwnershipAndNoConnectionQuota(t *testing.T) {
	b, e := Render(protocol.FirewallPolicy{Enabled: true, Protect: true, TCPPorts: []int{443}, UDPPorts: []int{443}}, true, []int{2222})
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, expected := range []string{"flush ruleset", "2222", "ct direction reply", "nd-neighbor-solicit", "redirect to :53", "banned_v6_64"} {
		if !strings.Contains(s, expected) {
			t.Fatal("missing " + expected)
		}
	}
	if strings.Contains(s, "ct count") || strings.Contains(s, "conn_limited") {
		t.Fatal("conntrack quota retained")
	}
}
func TestConfirmationAndRollback(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "confirm"}[confirm], func(t *testing.T) {
			dir := t.TempDir()
			f := &fakeRunner{}
			m := &Manager{Dir: dir, ConfigPath: filepath.Join(dir, "nftables.conf"), Executable: "/usr/local/bin/xnodectl", Runner: f}
			p, e := m.Apply(context.Background(), "request", protocol.FirewallPolicy{Enabled: true, TCPPorts: []int{443}}, false)
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(strings.Join(f.calls, "\n"), "--on-active=45s") {
				t.Fatal("no independent watchdog")
			}
			if confirm {
				if e = m.Confirm(context.Background(), p.ID); e != nil {
					t.Fatal(e)
				}
				if _, e = os.Stat(m.ConfigPath); e != nil {
					t.Fatal(e)
				}
			}
			before := len(f.calls)
			if e = m.Rollback(context.Background()); e != nil {
				t.Fatal(e)
			}
			if confirm && len(f.calls) != before {
				t.Fatal("confirmed policy rolled back")
			}
			if !confirm && !strings.Contains(strings.Join(f.calls[before:], "\n"), "rollback.nft") {
				t.Fatal("previous rules not restored")
			}
		})
	}
}
