package firewall

import (
	"bytes"
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Kernel-assigned set IDs are transaction-local and are not rule semantics.
func normalized(e expr.Any) expr.Any {
	switch e := e.(type) {
	case *expr.Lookup:
		copy := *e
		copy.SetID = 0
		return &copy
	case *expr.Dynset:
		copy := *e
		copy.SetID = 0
		copy.Exprs = make([]expr.Any, len(e.Exprs))
		for i, nested := range e.Exprs {
			copy.Exprs[i] = normalized(nested)
		}
		return &copy
	default:
		return e
	}
}
func sameExpressions(a, b []expr.Any) (bool, error) {
	if len(a) != len(b) {
		return false, nil
	}
	for i := range a {
		left, err := expr.Marshal(byte(nftables.TableFamilyINet), normalized(a[i]))
		if err != nil {
			return false, err
		}
		right, err := expr.Marshal(byte(nftables.TableFamilyINet), normalized(b[i]))
		if err != nil {
			return false, err
		}
		if !bytes.Equal(left, right) {
			return false, nil
		}
	}
	return true, nil
}

type ruleWriter interface {
	DelRule(*nftables.Rule) error
	ReplaceRule(*nftables.Rule) *nftables.Rule
	InsertRule(*nftables.Rule) *nftables.Rule
	AddRule(*nftables.Rule) *nftables.Rule
}

// Retain an ordered subsequence; insert before the next retained handle. New
// kernel handles are not needed to order several insertions in one transaction.
func reconcileRules(c ruleWriter, current, desired []*nftables.Rule) error {
	indices := map[string]int{}
	for i, r := range desired {
		id := string(r.UserData)
		if _, ok := indices[id]; ok {
			return fmt.Errorf("duplicate rule ID %q", id)
		}
		indices[id] = i
	}
	retained := map[string]*nftables.Rule{}
	last := -1
	for _, r := range current {
		id := string(r.UserData)
		index, ok := indices[id]
		if ok && index > last {
			retained[id] = r
			last = index
		} else if err := c.DelRule(r); err != nil {
			return err
		}
	}
	next := make([]uint64, len(desired))
	anchor := uint64(0)
	for i := len(desired) - 1; i >= 0; i-- {
		next[i] = anchor
		if r := retained[string(desired[i].UserData)]; r != nil {
			anchor = r.Handle
		}
	}
	for i, r := range desired {
		if old := retained[string(r.UserData)]; old != nil {
			equal, err := sameExpressions(old.Exprs, r.Exprs)
			if err != nil {
				return err
			}
			if !equal {
				copy := *r
				copy.Handle = old.Handle
				c.ReplaceRule(&copy)
			}
		} else {
			copy := *r
			if next[i] != 0 {
				copy.Position = next[i]
				c.InsertRule(&copy)
			} else {
				c.AddRule(&copy)
			}
		}
	}
	return nil
}
