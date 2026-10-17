package firewall

import (
	"fmt"
	"github.com/google/nftables"
	"reflect"
)

func (b *policyPlan) reconcileSets(c *nftables.Conn, exists bool) error {
	existing := map[string]*nftables.Set{}
	if exists {
		sets, err := c.GetSets(b.table)
		if err != nil {
			return err
		}
		for _, s := range sets {
			existing[s.Name] = s
		}
	}
	for _, spec := range b.sets {
		old := existing[spec.set.Name]
		if old == nil {
			if err := c.AddSet(spec.set, spec.elements); err != nil {
				return err
			}
			continue
		}
		if old.KeyType.Name != spec.set.KeyType.Name || old.Interval != spec.set.Interval || old.Dynamic != spec.set.Dynamic || old.HasTimeout != spec.set.HasTimeout || old.Timeout != spec.set.Timeout {
			return fmt.Errorf("incompatible existing set %s; refusing to discard live state", old.Name)
		}
		if old.Dynamic || spec.preserve {
			continue
		}
		current, err := c.GetSetElements(old)
		if err != nil {
			return err
		}
		add, remove := setDelta(current, spec.elements)
		if len(remove) > 0 {
			if err := c.SetDeleteElements(old, remove); err != nil {
				return err
			}
		}
		if len(add) > 0 {
			if err := c.SetAddElements(old, add); err != nil {
				return err
			}
		}
	}
	return nil
}
func (b *policyPlan) reconcileCounters(c *nftables.Conn, exists bool) error {
	names := map[string]bool{}
	if exists {
		objects, err := c.GetObjects(b.table)
		if err != nil {
			return err
		}
		for _, o := range objects {
			if o, ok := o.(*nftables.CounterObj); ok {
				names[o.Name] = true
			}
		}
	}
	for _, name := range counterNames {
		if !names[name] {
			c.AddObj(&nftables.CounterObj{Table: b.table, Name: name})
		}
	}
	return nil
}
func (b *policyPlan) reconcileChains(c *nftables.Conn, exists bool) error {
	existing := map[string]*nftables.Chain{}
	if exists {
		chains, err := c.ListChains()
		if err != nil {
			return err
		}
		for _, chain := range chains {
			if chain.Table.Name == b.table.Name && chain.Table.Family == b.table.Family {
				existing[chain.Name] = chain
			}
		}
	}
	// Declare all jump targets before programming rules.
	for _, chain := range b.chains {
		old := existing[chain.Name]
		if old == nil || !sameChain(old, chain) {
			c.AddChain(chain)
		}
	}
	for _, chain := range b.chains {
		if b.preserveRules[chain.Name] && existing[chain.Name] != nil {
			delete(existing, chain.Name)
			continue
		}
		var current []*nftables.Rule
		if existing[chain.Name] != nil {
			var err error
			current, err = c.GetRules(b.table, chain)
			if err != nil {
				return err
			}
		}
		if err := reconcileRules(c, current, b.rules[chain.Name]); err != nil {
			return err
		}
		delete(existing, chain.Name)
	}
	// Full ownership also removes obsolete or unrecognized chains in our table.
	for _, chain := range existing {
		c.FlushChain(chain)
	}
	for _, chain := range existing {
		c.DelChain(chain)
	}
	return nil
}
func sameChain(a, b *nftables.Chain) bool {
	return a.Type == b.Type && reflect.DeepEqual(a.Hooknum, b.Hooknum) && reflect.DeepEqual(a.Priority, b.Priority) && reflect.DeepEqual(a.Policy, b.Policy)
}
