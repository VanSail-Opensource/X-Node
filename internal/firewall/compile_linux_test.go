package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"os"
	"strings"
	"testing"
)

func TestPolicyCompilationAndBoundaries(t *testing.T) {
	p := policy()
	p.TCPPorts = []int{1, 65535, 443, 443}
	p.UDPPorts = []int{65535}
	p.AllowPrefixes = []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "10.1.0.0/16"}
	b, err := compile(p, true, []int{2222})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, s := range b.sets {
		counts[s.set.Name] = len(s.elements)
	}
	if counts["lan_v4"] != 2 || counts["lan_v6"] != 2 || counts["tcp_ports"] != 4 || counts["udp_ports"] != 1 {
		t.Fatal("prefixes expanded or ports duplicated", counts)
	}
	if len(b.rules["dns_output"]) != 4 {
		t.Fatal("missing dual-stack TCP/UDP DNS")
	}
	for chain, rules := range b.rules {
		ids := map[string]bool{}
		for _, r := range rules {
			if ids[string(r.UserData)] {
				t.Fatal("duplicate rule ID", chain)
			}
			ids[string(r.UserData)] = true
			for _, e := range r.Exprs {
				if _, ok := e.(*expr.Connlimit); ok {
					t.Fatal("conntrack quota retained")
				}
				if _, err := expr.Marshal(byte(nftables.TableFamilyINet), e); err != nil {
					t.Fatal("unserializable rule", chain, err)
				}
			}
		}
	}
	p.TCPPorts = []int{0}
	if _, err := compile(p, false, []int{22}); err == nil {
		t.Fatal("invalid port accepted")
	}
}
func TestSetDeltaDoesNotFlushUnchangedElements(t *testing.T) {
	a := []nftables.SetElement{{Key: []byte{0, 1}}, {Key: []byte{255, 255}}}
	b := []nftables.SetElement{{Key: []byte{255, 255}}, {Key: []byte{1, 1}}}
	add, remove := setDelta(a, b)
	if len(add) != 1 || len(remove) != 1 || remove[0].Key[1] != 1 || add[0].Key[0] != 1 {
		t.Fatal("incorrect incremental delta")
	}
}
func TestBootUnitMatchesDeployment(t *testing.T) {
	b, err := os.ReadFile("../../deploy/x-node-firewall.service")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(b), "\r\n", "\n") != bootUnit {
		t.Fatal("installed and migrated boot units differ")
	}
	b, err = os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "After=local-fs.target systemd-sysctl.service nftables.service") || strings.Contains(string(b), "Before=nftables.service") {
		t.Fatal("installer has obsolete ordering")
	}
}
