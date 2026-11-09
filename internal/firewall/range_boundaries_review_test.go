//go:build linux

package firewall

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestFirewallRangeReviewUpperPortIntervalSentinel(t *testing.T) {
	for _, first := range []int{1, 65534, 65535} {
		p := policy()
		p.UDPPortRanges = []protocol.PortRange{{From: first, To: 65535}}
		plan, err := compile(p, false, []int{22})
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, spec := range plan.sets {
			if spec.set.Name != "udp_ports_v2" {
				continue
			}
			found = true
			if !spec.set.Interval || len(spec.elements) != 2 {
				t.Fatalf("range %d-65535 was expanded or lost: %+v", first, spec)
			}
			if !spec.elements[0].IntervalEnd || !bytes.Equal(spec.elements[0].Key, []byte{0, 0}) || spec.elements[1].IntervalEnd || binary.BigEndian.Uint16(spec.elements[1].Key) != uint16(first) {
				t.Fatalf("range %d-65535 has invalid wrap boundary: %+v", first, spec.elements)
			}
		}
		if !found {
			t.Fatal("range policy did not select the versioned UDP interval set")
		}
	}
}

func TestFirewallRangeReviewMapValueChangesReplaceExistingElements(t *testing.T) {
	old := nftables.SetElement{Key: []byte{255, 255}, Val: []byte{1, 187}}
	next := nftables.SetElement{Key: []byte{255, 255}, Val: []byte{1, 188}}
	add, remove := setDelta([]nftables.SetElement{old}, []nftables.SetElement{next})
	if len(add) != 1 || len(remove) != 1 || !bytes.Equal(add[0].Val, next.Val) || !bytes.Equal(remove[0].Val, old.Val) {
		t.Fatalf("changed map destination was ignored: add=%+v remove=%+v", add, remove)
	}
	add, remove = setDelta([]nftables.SetElement{next}, []nftables.SetElement{next})
	if len(add) != 0 || len(remove) != 0 {
		t.Fatalf("unchanged map value was unnecessarily replaced: add=%+v remove=%+v", add, remove)
	}
}

func TestFirewallRangeReviewForwardAcceptRetainsOriginalTuple(t *testing.T) {
	p := policy()
	p.Forward = []protocol.Forward{{ListenIP: "198.51.100.8", Port: 65534, PortEnd: 65535, TargetIP: "192.0.2.10", TargetPort: 443, Network: "tcp"}}
	plan, err := compile(p, false, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, rule := range plan.rules["forward"] {
		if !strings.Contains(string(rule.UserData), ":forward-") {
			continue
		}
		checked++
		var originalPort, originalAddress bool
		for _, expression := range rule.Exprs {
			ct, ok := expression.(*expr.Ct)
			if !ok || !ct.OptDirection || ct.Direction != expr.CtDirOriginal {
				continue
			}
			originalPort = originalPort || ct.Key == expr.CtKeyPROTODST
			originalAddress = originalAddress || ct.Key == expr.CtKeyDST || ct.Key == expr.CtKeyDSTIP
		}
		if !originalPort || !originalAddress {
			t.Fatalf("translated target alone can authorize unrelated DNAT: originalPort=%t originalAddress=%t rule=%+v", originalPort, originalAddress, rule)
		}
	}
	if checked == 0 {
		t.Fatal("no scoped forward-accept rule compiled")
	}
}
