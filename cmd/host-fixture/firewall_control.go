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

func firewallControlChecks(ctx context.Context, manager *firewall.Manager, policy protocol.FirewallPolicy, runner host.Runner) error {
	guard, err := firewall.OpenGuard(manager.Dir, manager)
	if err != nil {
		return err
	}
	policy.MasterControlled = true
	guard.Configure(policy)
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	done, kernelDone := make(chan struct{}), make(chan struct{})
	reports := make(chan protocol.Message, 32)
	go func() {
		defer close(done)
		guard.Run(child, func(message protocol.Message, _ bool) bool {
			select {
			case reports <- message:
			default:
			}
			return true
		})
	}()
	go func() { defer close(kernelDone); guard.RunKernel(child) }()
	defer func() { cancel(); <-done; <-kernelDone }()
	if err = waitFixture(ctx, func() bool { return guard.Status().KernelReady }); err != nil {
		return fmt.Errorf("NFLOG collector: %w", err)
	}
	stop, err := startEcho(ctx, "", "9443")
	if err != nil {
		return err
	}
	defer stop()
	stopPeer, err := startEcho(ctx, "xnode-client", "9001")
	if err != nil {
		return err
	}
	defer stopPeer()
	for range 3 {
		_, _ = runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "198.18.0.1", "9444", "tcp")
	}
	var detection protocol.FirewallEvent
	if err = waitFixture(ctx, func() bool {
		for {
			select {
			case message := <-reports:
				if message.Type == "firewall.events" {
					var batch protocol.FirewallEvents
					if protocol.Decode(message.Data, &batch) == nil {
						for _, event := range batch.Events {
							if event.Kind == "detected" && event.IP == "198.18.0.2" {
								detection = event
								return true
							}
						}
					}
				}
			default:
				return false
			}
		}
	}); err != nil {
		return fmt.Errorf("closed-port report: %w", err)
	}
	if detection.Count < 3 || detection.Rule != "closed_port" || guard.Status().ActiveBans != 0 {
		return fmt.Errorf("detector did not remain report-only")
	}
	guard.Acknowledge([]string{detection.ID})
	if _, err = runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "198.18.0.1", "9443", "tcp"); err != nil {
		return fmt.Errorf("detector autonomously banned: %w", err)
	}
	now := time.Now().UTC()
	bans := []protocol.FirewallBan{{Prefix: "198.18.0.2", Generation: "vm-ban", Until: now.Add(time.Minute), RefreshSeconds: 3600}, {Prefix: "2001:db8:1::/64", Generation: "vm-ban", Until: now.Add(time.Minute), RefreshSeconds: 3600}}
	if err = guard.Update(ctx, protocol.FirewallUpdate{Version: 1, SnapshotID: "vm-ban", Bans: bans}); err != nil {
		return err
	}
	if _, err = runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "198.18.0.1", "9443", "tcp"); err == nil {
		return fmt.Errorf("master ban did not reach nftables")
	}
	for _, address := range []string{"198.18.0.2", "2001:db8:1::2"} {
		if _, err = runner.Run(ctx, "python3", "-c", echoProbe, address, "9001", "tcp"); err != nil {
			return fmt.Errorf("ban blocked outbound/reply traffic: %w", err)
		}
	}
	if err = waitFixture(ctx, func() bool { return banRemaining("banned_v4", netip.MustParseAddr("198.18.0.2")) > 30*time.Minute }); err != nil {
		return fmt.Errorf("repeat hit did not refresh ban: %w", err)
	}
	exemption := protocol.FirewallExemption{IP: "2001:db8:1::2", Generation: "vm-exempt", Until: now.Add(time.Minute)}
	if err = guard.Update(ctx, protocol.FirewallUpdate{Version: 2, SnapshotID: "vm-exempt", Exemptions: []protocol.FirewallExemption{exemption}}); err != nil {
		return err
	}
	if _, err = runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "2001:db8:1::1", "9443", "tcp"); err != nil {
		return fmt.Errorf("exact IPv6 exemption: %w", err)
	}
	if _, err = runner.Run(ctx, "ip", "-n", "xnode-client", "-6", "addr", "add", "2001:db8:1::3/64", "dev", "peer", "nodad"); err != nil {
		return err
	}
	if _, err = runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "2001:db8:1::1", "9443", "tcp", "2001:db8:1::3"); err == nil {
		return fmt.Errorf("exact exemption released entire IPv6 subnet")
	}
	if err = cidrExemptionChecks(ctx, guard, runner); err != nil {
		return err
	}
	persisted := protocol.FirewallBan{Prefix: "203.0.113.90", Generation: "vm-persist", Until: now.Add(time.Hour), RefreshSeconds: 3600}
	source := protocol.FirewallSource{ID: "vm-source", Generation: "vm-source", Until: now.Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"8.0.0.0/8", "2001:4860::/32"}}
	if err = guard.Update(ctx, protocol.FirewallUpdate{Version: 4, SnapshotID: "vm-persist", Bans: []protocol.FirewallBan{persisted}, Remove: []string{"198.18.0.2", "2001:db8:1::/64"}, RemoveExemptions: []string{"2001:db8:1::2", "2001:db8:1::/64"}}); err != nil {
		return err
	}
	if err = guard.Sync(ctx, protocol.FirewallUpdate{Version: 4, SourcesOnly: true, SnapshotID: "vm-source-persist", Final: true, SourcesComplete: true, Sources: []protocol.FirewallSource{source}}); err != nil {
		return err
	}
	if banRemaining("banned_v4", netip.MustParseAddr("203.0.113.90")) <= 0 {
		return fmt.Errorf("durable ban was not installed")
	}
	if err = countryRangeChecks(ctx, guard, manager, policy, runner); err != nil {
		return err
	}
	return firewallMemoryChecks(ctx, guard)
}
func waitFixture(ctx context.Context, ready func() bool) error {
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("fixture condition timed out")
		case <-ticker.C:
		}
	}
}
func banRemaining(name string, ip netip.Addr) time.Duration {
	c := &nftables.Conn{}
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	set, err := c.GetSetByName(table, name)
	if err != nil {
		return 0
	}
	elements, err := c.GetSetElements(set)
	if err != nil {
		return 0
	}
	for _, element := range elements {
		if string(element.Key) == string(ip.AsSlice()) {
			return element.Expires
		}
	}
	return 0
}
