package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Large inventories are populated in unreferenced generation sets through
// bounded transactions. Only the final selector swap changes packet behavior.
func prepareSources(ctx context.Context, sources []protocol.FirewallSource) (map[string]string, error) {
	return prepareSourcesFrom(ctx, "", sources)
}
func prepareSourcesFrom(ctx context.Context, dir string, sources []protocol.FirewallSource) (map[string]string, error) {
	targets := map[string]string{}
	active, err := activeSourceSets(ctx)
	if err != nil {
		return nil, err
	}
	if err = cleanupSourceSets(ctx, active); err != nil {
		return nil, err
	}
	for _, v6 := range []bool{false, true} {
		suffix, key := "v4", nftables.TypeIPAddr
		if v6 {
			suffix, key = "v6", nftables.TypeIP6Addr
		}
		hash := sha256.New()
		count := 0
		var last diskRange
		err = walkSourceRecords(ctx, dir, sources, v6, func(record diskRange) error { _, err := hash.Write(record[:]); count++; last = record; return err })
		if err != nil {
			return nil, err
		}
		if count == 0 {
			targets[suffix] = ""
			continue
		}
		name := "xnode_src_" + suffix + "_" + hex.EncodeToString(hash.Sum(nil))[:16]
		targets[suffix] = name
		if active[suffix] == name {
			continue
		}
		set := &nftables.Set{Table: &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}, Name: name, KeyType: key, Interval: true, AutoMerge: true}
		if err = populateRangeSet(ctx, set, last, count, func(visit func(diskRange) error) error { return walkSourceRecords(ctx, dir, sources, v6, visit) }); err != nil {
			return nil, err
		}

	}
	return targets, nil
}
func activeSourceSets(ctx context.Context) (map[string]string, error) {
	c, close, err := connection(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	active := map[string]string{}
	for _, suffix := range []string{"v4", "v6"} {
		rules, err := c.GetRules(table, &nftables.Chain{Table: table, Name: "source_lookup_" + suffix})
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			for _, item := range rule.Exprs {
				if lookup, ok := item.(*expr.Lookup); ok {
					active[suffix] = lookup.SetName
				}
			}
		}
	}
	return active, nil
}
func cleanupSourceSets(ctx context.Context, keep map[string]string) error {
	c, close, err := connection(ctx)
	if err != nil {
		return err
	}
	defer close()
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	sets, err := c.GetSets(table)
	if err != nil {
		return err
	}
	changed := false
	for _, set := range sets {
		if !strings.HasPrefix(set.Name, "xnode_src_") {
			continue
		}
		retained := false
		for _, name := range keep {
			if set.Name == name {
				retained = true
			}
		}
		if !retained {
			c.DelSet(set)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), errors.New("source set cleanup interrupted"))
	}
	return c.Flush()
}

func populateSource(ctx context.Context, set *nftables.Set, elements []nftables.SetElement) error {
	c, close, err := connection(ctx)
	if err != nil {
		return err
	}
	defer close()
	if err = c.SetAddElements(set, elements); err != nil {
		return err
	}
	return c.Flush()
}
