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

func (nativeBackend) Protected(ctx context.Context, items []protocol.FirewallExemption) error {
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
	desired := map[string][]nftables.SetElement{"trusted_v4": {}, "trusted_v6": {}}
	for _, item := range items {
		ip, err := netip.ParseAddr(item.IP)
		if err != nil {
			return err
		}
		name := "trusted_v4"
		if ip.Is6() {
			name = "trusted_v6"
		}
		remaining := time.Until(item.Until)
		if remaining > 0 {
			desired[name] = append(desired[name], nftables.SetElement{Key: ip.AsSlice(), Timeout: remaining})
		}
	}
	for name, elements := range desired {
		var set *nftables.Set
		for _, candidate := range sets {
			if candidate.Name == name {
				set = candidate
				break
			}
		}
		if set == nil {
			return errors.New("protected source sets await firewall activation")
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
	return c.Flush()
}
