package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"testing"
)

type ruleRecorder struct {
	rules   []*nftables.Rule
	changes int
}

func (c *ruleRecorder) DelRule(r *nftables.Rule) error {
	c.changes++
	for i, old := range c.rules {
		if old.Handle == r.Handle {
			c.rules = append(c.rules[:i], c.rules[i+1:]...)
			break
		}
	}
	return nil
}
func (c *ruleRecorder) ReplaceRule(r *nftables.Rule) *nftables.Rule {
	c.changes++
	for i, old := range c.rules {
		if old.Handle == r.Handle {
			c.rules[i] = r
			break
		}
	}
	return r
}
func (c *ruleRecorder) InsertRule(r *nftables.Rule) *nftables.Rule {
	c.changes++
	for i, old := range c.rules {
		if old.Handle == r.Position {
			c.rules = append(c.rules, nil)
			copy(c.rules[i+1:], c.rules[i:])
			c.rules[i] = r
			break
		}
	}
	return r
}
func (c *ruleRecorder) AddRule(r *nftables.Rule) *nftables.Rule {
	c.changes++
	c.rules = append(c.rules, r)
	return r
}
func testRule(id string, handle uint64) *nftables.Rule {
	return &nftables.Rule{UserData: []byte(id), Handle: handle, Exprs: drop()}
}
func TestOrderedRuleReconciliation(t *testing.T) {
	for _, ids := range []string{"abc", "cab", "xyabc", "axbycz", "", "cba"} {
		t.Run(ids, func(t *testing.T) {
			current := []*nftables.Rule{testRule("a", 1), testRule("b", 2), testRule("c", 3)}
			c := &ruleRecorder{rules: append([]*nftables.Rule(nil), current...)}
			var desired []*nftables.Rule
			for _, id := range ids {
				desired = append(desired, testRule(string(id), 0))
			}
			if err := reconcileRules(c, current, desired); err != nil {
				t.Fatal(err)
			}
			got := ""
			for _, r := range c.rules {
				got += string(r.UserData)
			}
			if got != ids {
				t.Fatalf("got %q, want %q", got, ids)
			}
			if ids == "abc" && c.changes != 0 {
				t.Fatal("unchanged rules were replaced")
			}
		})
	}
}
func TestSameIDChangedExpressionsReplaced(t *testing.T) {
	old := testRule("stable", 7)
	want := testRule("stable", 0)
	want.Exprs = accept()
	c := &ruleRecorder{rules: []*nftables.Rule{old}}
	if err := reconcileRules(c, c.rules, []*nftables.Rule{want}); err != nil {
		t.Fatal(err)
	}
	if c.changes != 1 || c.rules[0].Handle != 7 {
		t.Fatal("changed rule not replaced in place")
	}
	same, err := sameExpressions(c.rules[0].Exprs, accept())
	if err != nil || !same {
		t.Fatal("changed expressions not applied", err)
	}
}
func TestKernelSetIDsDoNotCauseReplacement(t *testing.T) {
	a := []expr.Any{&expr.Dynset{SetID: 17, SetName: "meter", SrcRegKey: 1, Exprs: []expr.Any{&expr.Limit{Rate: 50}}}}
	b := []expr.Any{&expr.Dynset{SetName: "meter", SrcRegKey: 1, Exprs: []expr.Any{&expr.Limit{Rate: 50}}}}
	equal, err := sameExpressions(a, b)
	if err != nil || !equal {
		t.Fatal("kernel ID changed semantics", err)
	}
}
