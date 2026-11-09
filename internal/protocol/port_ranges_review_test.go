package protocol

import (
	"reflect"
	"testing"
)

func TestFirewallRangeReviewPreservesUpperBoundaryAndInput(t *testing.T) {
	input := FirewallPolicy{
		TCPPorts:      []int{65535, 1, 65534},
		TCPPortRanges: []PortRange{{From: 65535, To: 65535}, {From: 65533, To: 65534}},
		SSHPortRanges: []PortRange{{From: 22, To: 23}},
	}
	got, err := input.NormalizePortRanges()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.TCPPortRanges, []PortRange{{From: 65533, To: 65535}}) || !reflect.DeepEqual(got.TCPPorts, []int{1}) {
		t.Fatalf("upper-bound range or covered singletons changed: %+v", got)
	}
	if !reflect.DeepEqual(input.TCPPorts, []int{65535, 1, 65534}) || !reflect.DeepEqual(input.TCPPortRanges, []PortRange{{From: 65535, To: 65535}, {From: 65533, To: 65534}}) {
		t.Fatal("normalization mutated the caller's policy slices")
	}
	again, err := got.NormalizePortRanges()
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("normalization is not idempotent: %+v %v", again, err)
	}
}

func TestFirewallRangeReviewRejectsInvalidACLBounds(t *testing.T) {
	for _, interval := range []PortRange{
		{From: 0, To: 1}, {From: 65535, To: 65536}, {From: 2, To: 1}, {From: 1, To: 2, Network: "udp"},
	} {
		if _, err := (FirewallPolicy{SSHPortRanges: []PortRange{interval}}).NormalizePortRanges(); err == nil {
			t.Fatalf("invalid SSH interval accepted: %+v", interval)
		}
	}
}

func TestFirewallRangeReviewForwardOverlapDomains(t *testing.T) {
	base := Forward{Port: 65000, PortEnd: 65535, TargetIP: "192.0.2.10", TargetPort: 1000, Network: "udp"}
	for _, test := range []struct {
		name  string
		a, b  Forward
		valid bool
	}{
		{"empty wildcard overlaps specific", base, reviewForward(base, "198.51.100.2", "192.0.2.11", "udp", 65535), false},
		{"explicit wildcard overlaps specific", reviewForward(base, "0.0.0.0", "192.0.2.10", "udp", 65000), reviewForward(base, "198.51.100.2", "192.0.2.11", "udp", 65535), false},
		{"distinct concrete listeners", reviewForward(base, "198.51.100.1", "192.0.2.10", "udp", 65000), reviewForward(base, "198.51.100.2", "192.0.2.11", "udp", 65535), true},
		{"distinct protocols", base, reviewForward(base, "", "192.0.2.11", "tcp", 65535), true},
		{"distinct address families", base, reviewForward(base, "::", "2001:db8::10", "udp", 65535), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, pair := range [][]Forward{{test.a, test.b}, {test.b, test.a}} {
				_, err := (FirewallPolicy{Forward: pair}).NormalizePortRanges()
				if (err == nil) != test.valid {
					t.Fatalf("valid=%t error=%v pair=%+v", test.valid, err, pair)
				}
			}
		})
	}
}

func reviewForward(base Forward, listen, target, network string, start int) Forward {
	base.ListenIP, base.TargetIP, base.Network, base.Port = listen, target, network, start
	return base
}

func TestFirewallRangeReviewForwardMappingLengthsAndDuplicates(t *testing.T) {
	base := Forward{Port: 65534, PortEnd: 65535, TargetIP: "192.0.2.10", TargetPort: 443, Network: "tcp"}
	for _, test := range []struct {
		name      string
		targetEnd int
		valid     bool
	}{
		{"many to one", 0, true}, {"one to one", 444, true}, {"unequal lengths", 445, false}, {"target overflows", 65536, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := base
			f.TargetPortEnd = test.targetEnd
			_, err := (FirewallPolicy{Forward: []Forward{f}}).NormalizePortRanges()
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t error=%v", test.valid, err)
			}
		})
	}
	alias := base
	alias.ListenIP = "0.0.0.0"
	got, err := (FirewallPolicy{Forward: []Forward{base, alias}}).NormalizePortRanges()
	if err != nil || len(got.Forward) != 1 {
		t.Fatalf("equivalent wildcard forwarding rows were not deduplicated: %+v %v", got.Forward, err)
	}
}
