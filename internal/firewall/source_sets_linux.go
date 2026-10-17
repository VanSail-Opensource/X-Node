package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go4.org/netipx"
)

// Large inventories are populated in unreferenced generation sets through
// bounded transactions. Only the final selector swap changes packet behavior.
func prepareSources(ctx context.Context, sources []protocol.FirewallSource) (map[string]string, error) {
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
		ranges, err := sourceRanges(sources, v6)
		if err != nil {
			return nil, err
		}
		if len(ranges) == 0 {
			targets[suffix] = ""
			continue
		}
		hash := sha256.New()
		for _, r := range ranges {
			_, _ = hash.Write(r.From().AsSlice())
			_, _ = hash.Write(r.To().AsSlice())
		}
		name := "xnode_src_" + suffix + "_" + hex.EncodeToString(hash.Sum(nil))[:16]
		targets[suffix] = name
		if active[suffix] == name {
			continue
		}
		set := &nftables.Set{Table: &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}, Name: name, KeyType: key, Interval: true, AutoMerge: true}
		c, close, err := connection(ctx)
		if err != nil {
			return nil, err
		}
		if err = c.AddSet(set, nil); err == nil {
			err = c.Flush()
		}
		close()
		if err != nil {
			return nil, err
		}
		set.ID = 0
		var elements []nftables.SetElement
		if last := ranges[len(ranges)-1]; !last.To().Next().IsValid() {
			elements = append(elements, nftables.SetElement{Key: make([]byte, key.Bytes), IntervalEnd: true}, nftables.SetElement{Key: last.From().AsSlice()})
			ranges = ranges[:len(ranges)-1]
		}
		for _, r := range ranges {
			elements = append(elements, nftables.SetElement{Key: r.From().AsSlice()}, nftables.SetElement{Key: r.To().Next().AsSlice(), IntervalEnd: true})
			if len(elements) >= 512 {
				if err = populateSource(ctx, set, elements); err != nil {
					return nil, err
				}
				elements = nil
			}
		}
		if len(elements) > 0 {
			if err = populateSource(ctx, set, elements); err != nil {
				return nil, err
			}
		}

	}
	return targets, nil
}
func sourceRanges(sources []protocol.FirewallSource, v6 bool) ([]netipx.IPRange, error) {
	var builder netipx.IPSetBuilder
	now := time.Now()
	for _, source := range sources {
		if source.Until.After(now) {
			for _, raw := range source.Prefixes {
				prefix, err := protocol.FirewallPrefix(raw)
				if err != nil {
					return nil, err
				}
				if prefix.Addr().Is6() == v6 {
					builder.AddPrefix(prefix)
				}
			}
		}
	}
	index, err := builder.IPSet()
	if err != nil {
		return nil, err
	}
	return index.Ranges(), nil
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
