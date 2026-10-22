package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
)

func protectFixtureClient(enabled bool) error {
	c := &nftables.Conn{}
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	for _, pair := range []struct{ set, ip string }{{"trusted_v4", "198.18.0.2"}, {"trusted_v6", "2001:db8:1::2"}} {
		set, err := c.GetSetByName(table, pair.set)
		if err != nil {
			return err
		}
		items := []nftables.SetElement{{Key: netip.MustParseAddr(pair.ip).AsSlice(), Timeout: time.Minute}}
		if enabled {
			err = c.SetAddElements(set, items)
		} else {
			err = c.SetDeleteElements(set, items)
		}
		if err != nil {
			return err
		}
	}
	return c.Flush()
}

func probeModeChecks(ctx context.Context, m *firewall.Manager, p protocol.FirewallPolicy, r host.Runner) error {
	for _, protect := range []bool{false, true} {
		p.Protect = protect
		tx, err := m.Apply(ctx, fmt.Sprintf("fixture-probe-%t", protect), p, false)
		if err != nil {
			return err
		}
		if err = m.Confirm(ctx, tx.ID); err != nil {
			return err
		}
		if err = packetChecks(ctx, r); err != nil {
			return fmt.Errorf("probe=%t: %w", protect, err)
		}
		if err = protectFixtureClient(true); err != nil {
			return err
		}
		if err = packetChecks(ctx, r); err != nil {
			return fmt.Errorf("protected probe=%t: %w", protect, err)
		}
		if err = protectFixtureClient(false); err != nil {
			return err
		}
	}
	return nil
}
