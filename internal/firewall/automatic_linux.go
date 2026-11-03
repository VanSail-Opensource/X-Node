//go:build linux

package firewall

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
)

func automaticSets(c *nftables.Conn) (map[string]*nftables.Set, error) {
	sets, err := c.GetSets(&nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet})
	if err != nil {
		return nil, err
	}
	result := map[string]*nftables.Set{}
	for _, set := range sets {
		if set.Name == "leased_v4" || set.Name == "leased_v6" {
			result[set.Name] = set
		}
	}
	return result, nil
}

func (nativeBackend) AutomaticExisting(ctx context.Context) ([]protocol.FirewallExemption, error) {
	c, close, err := connection(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	sets, err := automaticSets(c)
	if err != nil {
		return nil, err
	}
	var result []protocol.FirewallExemption
	for _, set := range sets {
		items, err := c.GetSetElements(set)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			ip, ok := netip.AddrFromSlice(item.Key)
			if !ok {
				return nil, errors.New("invalid automatic kernel address")
			}
			if item.Expires > 0 {
				result = append(result, protocol.FirewallExemption{IP: ip.Unmap().String(), Generation: "automatic", Until: time.Now().Add(item.Expires)})
			}
			if len(result) > protocol.MaxAutomaticLeases {
				return nil, errors.New("automatic kernel capacity exceeded")
			}
		}
	}
	return result, nil
}

func (nativeBackend) Automatic(ctx context.Context, items []protocol.FirewallExemption) error {
	c, close, err := connection(ctx)
	if err != nil {
		return err
	}
	defer close()
	sets, err := automaticSets(c)
	if err != nil {
		return err
	}
	desired := map[string][]nftables.SetElement{}
	for _, item := range items {
		ip, err := netip.ParseAddr(item.IP)
		if err != nil {
			return errors.New("invalid automatic kernel address")
		}
		name := "leased_v4"
		if ip.Is6() {
			name = "leased_v6"
		}
		if remaining := time.Until(item.Until); remaining > 0 {
			desired[name] = append(desired[name], nftables.SetElement{Key: ip.AsSlice(), Timeout: remaining})
		}
	}
	for name, additions := range desired {
		set := sets[name]
		if set == nil {
			return errors.New("automatic source sets await firewall activation")
		}
		current, err := c.GetSetElements(set)
		if err != nil {
			return err
		}
		// Only keys in this batch may change. Unknown old process grants remain
		// protected by their existing kernel deadline until locally expired.
		wanted := map[string]bool{}
		for _, item := range additions {
			wanted[string(item.Key)] = true
		}
		var selected []nftables.SetElement
		for _, item := range current {
			if wanted[string(item.Key)] {
				selected = append(selected, item)
			}
		}
		add, remove := timeoutDelta(selected, additions)
		if err := changeElements(c, set, remove, false); err != nil {
			return err
		}
		if err := changeElements(c, set, add, true); err != nil {
			return err
		}
	}
	return c.Flush()
}
