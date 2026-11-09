package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
)

func rangeStateChecks(ctx context.Context, m *firewall.Manager, baseline protocol.FirewallPolicy, r host.Runner) error {
	apply := func(id string, p protocol.FirewallPolicy) error {
		tx, err := m.Apply(ctx, id, p, false)
		if err != nil {
			return err
		}
		return m.Confirm(ctx, tx.ID)
	}
	p := protocol.Clone(baseline)
	for i := range p.Forward {
		if p.Forward[i].TargetPortEnd != 0 {
			p.Forward[i].TargetPort++
			p.Forward[i].TargetPortEnd++
		}
	}
	if err := apply("fixture-range-value-edit", p); err != nil {
		return err
	}
	for _, port := range []string{"9002", "9003", "9004"} {
		stop, err := startEcho(ctx, "xnode-target", port, true)
		if err != nil {
			return err
		}
		defer stop()
	}
	for _, address := range []string{"198.18.0.1", "2001:db8:1::1"} {
		for _, network := range []string{"tcp", "udp"} {
			for offset := 0; offset < 3; offset++ {
				if _, err := r.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, address, strconv.Itoa(24600+offset), network, "", strconv.Itoa(9002+offset)); err != nil {
					return fmt.Errorf("updated deterministic map: %w", err)
				}
			}
		}
	}
	p.Forward = nil
	if err := apply("fixture-range-map-removal", p); err != nil {
		return err
	}
	c := &nftables.Conn{}
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	sets, err := c.GetSets(table)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if strings.HasPrefix(set.Name, "forward_ports_") {
			return fmt.Errorf("obsolete forwarding map retained")
		}
	}
	if os.Getenv("XNODE_LARGE_FIREWALL_CHECK") == "1" {
		p.Forward = []protocol.Forward{{ListenIP: "198.18.0.1", Port: 1, PortEnd: 65535, TargetIP: "198.18.0.6", TargetPort: 1, TargetPortEnd: 65535, Network: "tcp"}}
		if err := apply("fixture-range-largest-map", p); err != nil {
			return err
		}
		sets, err = c.GetSets(table)
		if err != nil {
			return err
		}
		found := false
		for _, set := range sets {
			if !strings.HasPrefix(set.Name, "forward_ports_") {
				continue
			}
			elements, err := c.GetSetElements(set)
			if err != nil || len(elements) != 65535 {
				return fmt.Errorf("largest map cardinality=%d: %w", len(elements), err)
			}
			found = true
		}
		if !found {
			return fmt.Errorf("largest forwarding map missing")
		}
	}
	return apply("fixture-range-restore", baseline)
}
