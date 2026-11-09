package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"net/netip"
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
func liveStateChecks(ctx context.Context, m *firewall.Manager, p protocol.FirewallPolicy, runner host.Runner) error {
	c := &nftables.Conn{}
	table := &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}
	ban, err := c.GetSetByName(table, "banned_v4_v2")
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
	meterBefore, err := freshSYNMeter(ctx, c, meters, runner)
	if err != nil {
		return err
	}
	if err := legacyBanFixture(c, table); err != nil {
		return err
	}
	p.TCPPorts = append(append([]int(nil), p.TCPPorts...), 8443)
	tx, err := m.Apply(ctx, "fixture-incremental", p, false)
	if err != nil {
		return err
	}
	if err = m.Confirm(ctx, tx.ID); err != nil {
		return err
	}
	for _, name := range []string{"banned_v4", "banned_v6_64"} {
		if _, err := c.GetSetByName(table, name); err == nil {
			return fmt.Errorf("legacy ban set survived migration")
		}
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
	if err != nil {
		return fmt.Errorf("read incremental SYN meters: %w", err)
	}
	found = false
	for _, entry := range meterAfter {
		if reflect.DeepEqual(entry.Key, meterBefore.Key) && entry.Expires > 0 {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("incremental update lost freshly observed SYN meter %s", netip.AddrFrom4([4]byte{198, 18, 0, 2}))
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

// Create fresh real input traffic so unrelated old meter expirations cannot
// masquerade as state loss while a slow disposable VM applies the next policy.
func freshSYNMeter(ctx context.Context, c *nftables.Conn, set *nftables.Set, runner host.Runner) (nftables.SetElement, error) {
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	key := []byte{198, 18, 0, 2}
	// Destroy is idempotent when an old entry already expired. Touch only the
	// fixture client's key; all other dynamic meters remain part of the audit.
	if err := c.SetDestroyElements(set, []nftables.SetElement{{Key: key}}); err != nil {
		return nftables.SetElement{}, fmt.Errorf("reset fixture SYN meter: %w", err)
	}
	if err := c.Flush(); err != nil {
		return nftables.SetElement{}, fmt.Errorf("commit fixture SYN meter reset: %w", err)
	}
	stop, err := startEcho(probe, "", "9443")
	if err != nil {
		return nftables.SetElement{}, err
	}
	defer stop()
	if _, err = runner.Run(probe, "ip", "netns", "exec", "xnode-client", "python3", "-c", echoProbe, "198.18.0.1", "9443", "tcp", "198.18.0.2"); err != nil {
		return nftables.SetElement{}, fmt.Errorf("fresh untrusted SYN probe: %w", err)
	}
	entries, err := c.GetSetElements(set)
	if err != nil {
		return nftables.SetElement{}, fmt.Errorf("read fresh SYN meter: %w", err)
	}
	for _, entry := range entries {
		if reflect.DeepEqual(entry.Key, key) && entry.Expires > 0 {
			return entry, nil
		}
	}
	return nftables.SetElement{}, fmt.Errorf("fresh untrusted SYN did not create its expiring meter")
}

func watchdogCheck(ctx context.Context, m *firewall.Manager, p protocol.FirewallPolicy, runner host.Runner) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "--abandon")
	// stdout is the Pending JSON contract; utility diagnostics stay on stderr.
	command.Stderr = os.Stderr
	raw, err := command.Output()
	if err != nil {
		return fmt.Errorf("abandoned firewall subprocess: %w: %s", err, raw)
	}
	var tx firewall.Pending
	if err = json.Unmarshal(raw, &tx); err != nil {
		return err
	}
	if _, err = runner.Run(ctx, "nft", "--check", "--file", tx.Backup); err != nil {
		return fmt.Errorf("watchdog snapshot is not replayable: %w", err)
	}
	// Apply records its confirmation deadline before systemd-run arms the
	// independent timer. Start the fixture's 45-second timer window when the
	// applying process exits, then allow the bounded 30-second recovery and
	// 15 seconds for process startup/scheduler delay in emulated CI guests.
	rollbackDeadline := time.Now().Add(90 * time.Second)
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
		{"nft", "--check", "--file", tx.Backup},
		{"systemctl", "show", tx.Unit + ".timer", "--property=ActiveState,SubState,Result"},
		{"systemctl", "show", tx.Unit + ".service", "--property=ActiveState,SubState,Result,ExecMainStatus"},
		{"journalctl", "-u", tx.Unit + ".service", "--no-pager", "-n", "30"},
		{"systemctl", "list-jobs", "--no-pager"},
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

func bootDiagnostics(ctx context.Context, runner host.Runner) string {
	checks := [][]string{
		{"systemctl", "show", "x-node-firewall.service", "--property=ActiveState,SubState,Result,ExecMainStatus"},
		{"journalctl", "-u", "x-node-firewall.service", "--no-pager", "-n", "60"},
		{"cat", "/var/lib/x-node/firewall/pending.json"},
		{"nft", "list", "set", "inet", "x_node", "banned_v4_v2"},
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
	// SSH can become reachable before multi-user.target finishes. Wait for the
	// oneshot firewall restore instead of racing its UFW takeover and ban replay.
	startCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := r.Run(startCtx, "systemctl", "start", "x-node-firewall.service"); err != nil {
		return fmt.Errorf("boot firewall restore failed: %w: %s", err, bootDiagnostics(ctx, r))
	}
	if err := ownershipChecks(ctx, r, true); err != nil {
		return err
	}
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
	if banRemaining("banned_v4_v2", netip.MustParseAddr("203.0.113.90")) <= 0 {
		return fmt.Errorf("reboot lost a durable firewall ban")
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
	return ownershipChecks(ctx, r, false)
}
