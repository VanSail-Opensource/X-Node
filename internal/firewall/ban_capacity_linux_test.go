package firewall

import (
	"github.com/google/nftables/expr"
	"testing"
)

func TestVersionedBanSetCapacityAndRules(t *testing.T) {
	b, err := compile(policy(), false, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, spec := range b.sets {
		if legacyBanSet(spec.set.Name) {
			t.Fatal("legacy set compiled")
		}
		if spec.set.Name == banSetV4 || spec.set.Name == banSetV6 {
			found[spec.set.Name] = true
			if spec.set.Size != 1<<20 {
				t.Fatal(spec.set.Size)
			}
		}
	}
	if len(found) != 2 {
		t.Fatal("missing ban sets")
	}
	for _, rules := range b.rules {
		for _, rule := range rules {
			for _, e := range rule.Exprs {
				switch v := e.(type) {
				case *expr.Lookup:
					if legacyBanSet(v.SetName) {
						t.Fatal("legacy lookup")
					}
				case *expr.Dynset:
					if legacyBanSet(v.SetName) {
						t.Fatal("legacy dynamic update")
					}
				}
			}
		}
	}
	if !legacyBanSet("banned_v4") || !legacyBanSet("banned_v6_64") || legacyBanSet(banSetV4) || legacyBanSet("exempt_v4") {
		t.Fatal("unsafe cleanup selection")
	}
}
