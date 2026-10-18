//go:build linux

package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"syscall"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func countrySetName(generation string, v6 bool) string {
	hash := sha256.Sum256([]byte(generation))
	family := "v4"
	if v6 {
		family = "v6"
	}
	return "xnode_geoip_" + family + "_" + hex.EncodeToString(hash[:])[:16]
}

func activeCountrySets(ctx context.Context) (map[string]bool, error) {
	c, close, err := connection(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	rules, err := c.GetRules(table, &nftables.Chain{Table: table, Name: "input"})
	if errors.Is(err, syscall.ENOENT) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, rule := range rules {
		for _, item := range rule.Exprs {
			if lookup, ok := item.(*expr.Lookup); ok && strings.HasPrefix(lookup.SetName, "xnode_geoip_") {
				keep[lookup.SetName] = true
			}
		}
	}
	return keep, nil
}

func prepareCountrySets(ctx context.Context, dir string, policy *protocol.SourceGeoIPPolicy) error {
	if policy == nil || !policy.Reference {
		return nil
	}
	active, err := activeCountrySets(ctx)
	if err != nil {
		return err
	}
	if err = cleanupCountrySets(ctx, active); err != nil {
		return err
	}
	for _, v6 := range []bool{false, true} {
		name := countrySetName(policy.Generation, v6)
		if active[name] {
			continue
		}
		walk := func(visit func(diskRange) error) error {
			return mergeRangeFiles(ctx, []string{sourcePath(dir, "country", policy.Generation)}, func(record diskRange) error {
				if (record[0] == 6) == v6 {
					return visit(record)
				}
				return nil
			})
		}
		var last diskRange
		count := 0
		if err = walk(func(record diskRange) error { last = record; count++; return nil }); err != nil {
			return err
		}
		key := nftables.TypeIPAddr
		if v6 {
			key = nftables.TypeIP6Addr
		}
		set := &nftables.Set{Table: &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}, Name: name, KeyType: key, Interval: true, AutoMerge: true}
		if err = populateRangeSet(ctx, set, last, count, walk); err != nil {
			return err
		}
	}
	return nil
}

func cleanupCountrySets(ctx context.Context, keep map[string]bool) error {
	c, close, err := connection(ctx)
	if err != nil {
		return err
	}
	defer close()
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	sets, err := c.GetSets(table)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	changed := false
	for _, set := range sets {
		if strings.HasPrefix(set.Name, "xnode_geoip_") && !keep[set.Name] {
			c.DelSet(set)
			changed = true
		}
	}
	if changed {
		return c.Flush()
	}
	return nil
}
