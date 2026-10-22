package firewall

import (
	"context"
	"errors"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
)

func (b nativeBackend) StageSources(ctx context.Context, sources []protocol.FirewallSource) (map[string]string, error) {
	return prepareSourcesFrom(ctx, b.dir, sources)
}
func (b nativeBackend) Bans(ctx context.Context, bans []protocol.FirewallBan, exemptions []protocol.FirewallExemption, sources []protocol.FirewallSource, replaceSources bool) error {
	var targets map[string]string
	var err error
	if replaceSources {
		targets, err = prepareSourcesFrom(ctx, b.dir, sources)
		if err != nil {
			return err
		}
	}
	return b.ApplyBans(ctx, bans, exemptions, targets, true, replaceSources)
}
func (nativeBackend) ApplyBans(ctx context.Context, bans []protocol.FirewallBan, exemptions []protocol.FirewallExemption, targets map[string]string, applyBans, replaceSources bool) error {
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
	byName := map[string]*nftables.Set{}
	for _, set := range sets {
		byName[set.Name] = set
	}
	desired := map[string][]nftables.SetElement{banSetV4: {}, banSetV6: {}, "exempt_v4": {}, "exempt_v6": {}}
	now := time.Now()
	for _, ban := range bans {
		prefix, err := protocol.FirewallPrefix(ban.Prefix)
		if err != nil {
			return err
		}
		name := banSetV4
		if prefix.Addr().Is6() {
			name = banSetV6
		}
		remaining := ban.Until.Sub(now)
		if remaining <= 0 {
			continue
		}
		desired[name] = append(desired[name], nftables.SetElement{Key: prefix.Addr().AsSlice(), Timeout: remaining})
	}
	for _, exemption := range exemptions {
		prefix, err := protocol.ExemptionPrefix(exemption.IP)
		ip := prefix.Addr()
		if err != nil {
			return err
		}
		if prefix.Bits() != ip.BitLen() {
			continue
		}
		ip = ip.Unmap()
		name := "exempt_v4"
		if ip.Is6() {
			name = "exempt_v6"
		}
		remaining := exemption.Until.Sub(now)
		if remaining <= 0 {
			continue
		}
		desired[name] = append(desired[name], nftables.SetElement{Key: ip.AsSlice(), Timeout: remaining})
	}
	if applyBans {
		for name, elements := range desired {
			set := byName[name]
			if set == nil {
				return errors.New("firewall ban sets are not installed")
			}
			current, err := c.GetSetElements(set)
			if err != nil {
				return err
			}
			add, remove := timeoutDelta(current, elements)
			if err = changeElements(c, set, remove, false); err != nil {
				return err
			}
			if err = changeElements(c, set, add, true); err != nil {
				return err
			}
		}
	}

	if applyBans {
		for _, v6 := range []bool{false, true} {
			name := "exempt_prefix_v4"
			if v6 {
				name = "exempt_prefix_v6"
			}
			elements, err := exemptionRangeElements(exemptions, now, v6)
			if err != nil {
				return err
			}
			set := byName[name]
			if set == nil {
				if len(elements) == 0 {
					continue
				}
				return errors.New("CIDR exemption sets await configuration apply")
			}
			current, err := c.GetSetElements(set)
			if err != nil {
				return err
			}
			add, remove := timeoutDelta(current, elements)
			if len(add)+len(remove) == 0 {
				continue
			}
			c.FlushSet(set)
			if err = changeElements(c, set, elements, true); err != nil {
				return err
			}
		}
	}

	if replaceSources {
		for _, v6 := range []bool{false, true} {
			suffix, refresh := "v4", "source_match_v4"
			if v6 {
				suffix, refresh = "v6", "source_match_v6"
			}
			chain := &nftables.Chain{Table: table, Name: "source_lookup_" + suffix}
			current, e := c.GetRules(table, chain)
			if e != nil {
				return e
			}
			var desiredRules []*nftables.Rule
			if name := targets[suffix]; name != "" {
				desiredRules = []*nftables.Rule{{Table: table, Chain: chain, UserData: []byte("x-node:v1:source-current"), Exprs: cat(sourceSet(v6, name, false, false), goTo(refresh))}}
			}
			if err = reconcileRules(c, current, desiredRules); err != nil {
				return err
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = c.Flush(); err != nil {
		return err
	}
	if replaceSources {
		return cleanupSourceSets(ctx, targets)
	}
	return nil
}
