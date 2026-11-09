package firewall

import (
	"encoding/binary"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables/expr"
)

func TestForwardPortMapHasExactOffsetsAndBoundedRuleCount(t *testing.T) {
	p := policy()
	p.Forward = []protocol.Forward{{Port: 1, PortEnd: 65535, TargetIP: "192.0.2.10", TargetPort: 1, TargetPortEnd: 65535, Network: "udp"}}
	plan, err := compile(p, false, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.rules["prerouting"]) != 1 || len(plan.rules["forward"]) != 4 {
		t.Fatal("port map expanded into rules")
	}
	maps := 0
	for _, spec := range plan.sets {
		if !spec.set.IsMap {
			continue
		}
		maps++
		if len(spec.elements) != 65535 {
			t.Fatal("map lost ports", len(spec.elements))
		}
		for _, index := range []int{0, 32767, 65534} {
			item := spec.elements[index]
			if binary.BigEndian.Uint16(item.Key) != uint16(index+1) || binary.BigEndian.Uint16(item.Val) != uint16(index+1) {
				t.Fatal("map offset changed", index, item)
			}
		}
	}
	if maps != 1 {
		t.Fatal("wrong map count", maps)
	}
	for _, item := range plan.rules["prerouting"][0].Exprs {
		if nat, ok := item.(*expr.NAT); ok && nat.RegProtoMax != 0 {
			t.Fatal("random target range allocator used")
		}
	}
}

func TestManyToOneForwardDoesNotExpandPortMap(t *testing.T) {
	p := policy()
	p.Forward = []protocol.Forward{{Port: 1, PortEnd: 65535, TargetIP: "2001:db8::10", TargetPort: 443, Network: "tcp"}}
	plan, err := compile(p, false, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range plan.sets {
		if spec.set.IsMap {
			t.Fatal("many-to-one map expanded")
		}
	}
	if len(plan.rules["prerouting"]) != 1 {
		t.Fatal("range expanded into rules")
	}
}
