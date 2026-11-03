package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func automaticLeaseChecks(ctx context.Context, guard *firewall.Guard, manager *firewall.Manager, policy protocol.FirewallPolicy, runner host.Runner) error {
	until := time.Now().Add(5 * time.Second)
	update := protocol.AutomaticLeaseUpdate{Epoch: "vm-first", Leases: []protocol.AutomaticLeaseGrant{{IP: "9.9.9.19", Generation: 1, Until: until}, {IP: "2001:4860::19", Generation: 2, Until: until}}}
	for range 2 {
		if _, err := guard.GrantAutomatic(ctx, update); err != nil {
			return err
		}
	}
	// A new process hydrates prior deadlines from volatile kernel sets, without
	// recovering IP payloads from disk or shortening a former master's grant.
	restarted, err := firewall.OpenGuard(manager.Dir, manager)
	if err != nil {
		return err
	}
	restarted.Configure(policy)
	update.Epoch = "vm-second"
	for i := range update.Leases {
		update.Leases[i].Until = time.Now().Add(time.Second)
	}
	if _, err := restarted.GrantAutomatic(ctx, update); err != nil {
		return err
	}
	check := func(expected bool) error {
		for name, ip := range map[string]string{"leased_v4": "9.9.9.19", "leased_v6": "2001:4860::19"} {
			raw, err := runner.Run(ctx, "nft", "list", "set", "inet", "x_node", name)
			if err != nil {
				return err
			}
			if strings.Contains(string(raw), ip) != expected {
				return errors.New("automatic kernel deadline did not match expected state")
			}
		}
		return nil
	}
	if err := check(true); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(until) + 300*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	if err := check(false); err != nil {
		return err
	}
	fmt.Println("Automatic exact-IP grants, replay, restart hydration and local expiry passed")
	return nil
}
