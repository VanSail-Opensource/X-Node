//go:build linux

package firewall

import (
	"strings"
	"testing"

	"github.com/google/nftables/expr"
)

func TestAutomaticLeaseSetsAreExactAndDoNotBypassInputAdmission(t *testing.T) {
	plan, err := compile(policy(), false, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, spec := range plan.sets {
		if spec.set.Name == "leased_v4" || spec.set.Name == "leased_v6" {
			count++
			if spec.set.Interval || !spec.set.HasTimeout || !spec.preserve {
				t.Fatal("automatic lease bank widened addresses or lost local expiry")
			}
		}
	}
	if count != 2 {
		t.Fatal("missing automatic lease sets")
	}
	for chain, rules := range plan.rules {
		for _, rule := range rules {
			for _, expression := range rule.Exprs {
				if lookup, ok := expression.(*expr.Lookup); ok && strings.HasPrefix(lookup.SetName, "leased_") && chain != "blacklist" {
					t.Fatal("automatic lease bypassed an unrelated admission chain", chain)
				}
			}
		}
	}
	raw := []byte("table inet x_node {\n set leased_v4 {\n type ipv4_addr\n elements = { 9.9.9.19 timeout 1h }\n }\n set leased_v6 {\n type ipv6_addr\n elements = { 2001:4860::19 timeout 1h }\n }\n}\n")
	private, err := withoutVolatileProtection(raw)
	if err != nil || strings.Contains(string(private), "9.9.9.19") || strings.Contains(string(private), "2001:4860::19") {
		t.Fatal("automatic lease IP entered a rollback snapshot", err)
	}
}
