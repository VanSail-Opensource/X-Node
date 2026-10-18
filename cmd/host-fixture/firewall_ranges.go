package main

import (
	"context"
	"fmt"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func cidrExemptionChecks(ctx context.Context, guard *firewall.Guard, runner host.Runner) error {
	grant := protocol.FirewallExemption{IP: "2001:db8:1::/64", Generation: "vm-cidr", Until: time.Now().Add(3 * time.Second)}
	if err := guard.Update(ctx, protocol.FirewallUpdate{Version: 3, SnapshotID: "vm-cidr", Exemptions: []protocol.FirewallExemption{grant}}); err != nil {
		return err
	}
	probe := func(source string) error {
		_, err := runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "2001:db8:1::1", "9443", "tcp", source)
		return err
	}
	if err := probe("2001:db8:1::3"); err != nil {
		return fmt.Errorf("CIDR exemption: %w", err)
	}
	if err := waitFixture(ctx, func() bool { return probe("2001:db8:1::3") != nil }); err != nil {
		return fmt.Errorf("CIDR exemption did not expire: %w", err)
	}
	if err := probe("2001:db8:1::2"); err != nil {
		return fmt.Errorf("CIDR expiry erased paid exact exemption: %w", err)
	}
	return nil
}

func countryRangeChecks(ctx context.Context, guard *firewall.Guard, manager *firewall.Manager, policy protocol.FirewallPolicy, runner host.Runner) error {
	if ready, err := guard.SyncGeoIP(ctx, protocol.GeoIPChunk{Generation: "vm-country", Final: true, Prefixes: []string{"198.18.0.0/24"}}); err != nil || !ready {
		return fmt.Errorf("country staging: ready=%t: %w", ready, err)
	}
	country := policy
	country.SourceGeoIP = &protocol.SourceGeoIPPolicy{Generation: "vm-country", Reference: true, Listeners: []protocol.SourceGeoIPListener{{Port: 9443, Network: "tcp"}}}
	pending, err := manager.Apply(ctx, "vm-country", country, false)
	if err != nil {
		return err
	}
	if err = manager.Confirm(ctx, pending.ID); err != nil {
		return err
	}
	guard.Configure(country)
	if _, err = runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "198.18.0.1", "9443", "tcp"); err == nil {
		return fmt.Errorf("country source range did not block the listener")
	}
	pending, err = manager.Apply(ctx, "vm-country-remove", policy, false)
	if err != nil {
		return err
	}
	if err = manager.Confirm(ctx, pending.ID); err != nil {
		return err
	}
	guard.Configure(policy)
	if _, err = runner.Run(ctx, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "198.18.0.1", "9443", "tcp"); err != nil {
		return fmt.Errorf("country removal did not restore listener: %w", err)
	}
	return nil
}
