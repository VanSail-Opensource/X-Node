package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

func ruleHandles(c *nftables.Conn, t *nftables.Table) (map[string]uint64, error) {
	chains, err := c.ListChains()
	if err != nil {
		return nil, err
	}
	result := map[string]uint64{}
	for _, chain := range chains {
		if chain.Table.Name != t.Name || chain.Table.Family != t.Family {
			continue
		}
		rules, err := c.GetRules(t, chain)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			result[chain.Name+"/"+string(rule.UserData)] = rule.Handle
		}
	}
	return result, nil
}
func liveStateChecks(ctx context.Context, m *firewall.Manager, p protocol.FirewallPolicy) error {
	c := &nftables.Conn{}
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	ban, err := c.GetSetByName(table, "banned_v4")
	if err != nil {
		return err
	}
	if err = c.SetAddElements(ban, []nftables.SetElement{{Key: []byte{203, 0, 113, 7}, Timeout: time.Hour}}); err != nil {
		return err
	}
	c.AddTable(&nftables.Table{Name: "fixture_foreign", Family: nftables.TableFamilyINet})
	if err = c.Flush(); err != nil {
		return err
	}
	before, err := ruleHandles(c, table)
	if err != nil {
		return err
	}
	counterBefore, err := c.GetObject(&nftables.CounterObj{Table: table, Name: "blocked_requests"})
	if err != nil {
		return err
	}
	meters, err := c.GetSetByName(table, "syn_v4")
	if err != nil {
		return err
	}
	meterBefore, err := c.GetSetElements(meters)
	if err != nil || len(meterBefore) == 0 {
		return fmt.Errorf("SYN meter missing: %w", err)
	}
	p.TCPPorts = append(append([]int(nil), p.TCPPorts...), 8443)
	tx, err := m.Apply(ctx, "fixture-incremental", p, false)
	if err != nil {
		return err
	}
	if err = m.Confirm(ctx, tx.ID); err != nil {
		return err
	}
	after, err := ruleHandles(c, table)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("unchanged rule handles were replaced")
	}
	counterAfter, err := c.GetObject(&nftables.CounterObj{Table: table, Name: "blocked_requests"})
	if err != nil {
		return err
	}
	if counterBefore.(*nftables.CounterObj).Packets == 0 || counterAfter.(*nftables.CounterObj).Packets < counterBefore.(*nftables.CounterObj).Packets {
		return fmt.Errorf("named counter was reset")
	}
	bans, err := c.GetSetElements(ban)
	if err != nil {
		return err
	}
	found := false
	for _, e := range bans {
		if reflect.DeepEqual(e.Key, []byte{203, 0, 113, 7}) && e.Expires > 0 && e.Expires <= time.Hour {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("incremental update lost ban expiry")
	}
	meterAfter, err := c.GetSetElements(meters)
	if err != nil || len(meterAfter) < len(meterBefore) {
		return fmt.Errorf("incremental update lost meters: %w", err)
	}
	tables, err := c.ListTables()
	if err != nil {
		return err
	}
	for _, t := range tables {
		if t.Name == "fixture_foreign" {
			return fmt.Errorf("foreign table survived full ownership")
		}
	}
	return nil
}

func watchdogCheck(ctx context.Context, m *firewall.Manager, p protocol.FirewallPolicy, runner host.Runner) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	raw, err := exec.CommandContext(ctx, executable, "--abandon").CombinedOutput()
	if err != nil {
		return fmt.Errorf("abandoned firewall subprocess: %w: %s", err, raw)
	}
	var tx firewall.Pending
	if err = json.Unmarshal(raw, &tx); err != nil {
		return err
	}
	// Apply records its confirmation deadline before systemd-run arms the
	// independent timer. Start the fixture's 45-second timer window when the
	// applying process exits, then allow 15 seconds for scheduler delay.
	rollbackDeadline := time.Now().Add(60 * time.Second)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		status, ok := m.Status().(firewall.Pending)
		if ok && status.Status == "rolled_back" {
			return nil
		}
		if time.Now().After(rollbackDeadline) {
			return fmt.Errorf("independent watchdog did not restore policy: %s", watchdogDiagnostics(ctx, runner, tx))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func watchdogDiagnostics(ctx context.Context, runner host.Runner, tx firewall.Pending) string {
	checks := [][]string{
		{"systemctl", "show", tx.Unit + ".timer", "--property=ActiveState,SubState,Result"},
		{"systemctl", "show", tx.Unit + ".service", "--property=ActiveState,SubState,Result,ExecMainStatus"},
		{"journalctl", "-u", tx.Unit + ".service", "--no-pager", "-n", "30"},
		{"cat", "/var/lib/x-node/firewall/pending.json"},
	}
	var details strings.Builder
	for _, args := range checks {
		output, err := runner.Run(ctx, args[0], args[1:]...)
		fmt.Fprintf(&details, "%s: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
		if err != nil {
			fmt.Fprintf(&details, " (%v)", err)
		}
		details.WriteString("; ")
	}
	return details.String()
}

func afterReboot(ctx context.Context, r host.Runner) error {
	if _, err := r.Run(ctx, "nft", "list", "table", "inet", "x_node"); err != nil {
		return fmt.Errorf("native boot policy missing: %w", err)
	}
	raw, err := os.ReadFile("/etc/nftables.conf")
	if err != nil || len(raw) == 0 || raw[0] != '#' {
		return fmt.Errorf("boot still relies on generated rules: %w", err)
	}
	c := &nftables.Conn{}
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	rules, err := c.GetRules(table, &nftables.Chain{Table: table, Name: "dns_output"})
	if err != nil {
		return err
	}
	if len(rules) != 0 {
		return fmt.Errorf("boot enabled DNS before resolver readiness")
	}
	if _, err = r.Run(ctx, "xnodectl", "uninstall"); err != nil {
		return err
	}
	if _, err = r.Run(ctx, "nft", "list", "table", "inet", "x_node"); err == nil {
		return fmt.Errorf("uninstall retained managed rules")
	}
	if _, err = r.Run(ctx, "nft", "list", "table", "inet", "fixture_original"); err != nil {
		return fmt.Errorf("uninstall lost original rules: %w", err)
	}
	return nil
}
