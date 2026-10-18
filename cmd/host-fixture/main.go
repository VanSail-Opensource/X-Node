// host-fixture is only executed in marked disposable Debian/Ubuntu VMs.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Software-emulated guests can spend well over the production 30-second
// recovery budget in systemd and UFW process startup.
const recoveryTimeout = 3 * time.Minute

func main() {
	if e := checkDisposableHost(); e != nil {
		fail(e)
	}
	// UFW invokes Python and many iptables processes under software-emulated CI.
	// Keep the overall fixture bounded independently of the unchanged 45s watchdog.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	runner := fixtureRunner{}
	if len(os.Args) > 1 && os.Args[1] == "--abandon" {
		m := &firewall.Manager{Dir: "/var/lib/x-node/firewall", ConfigPath: "/etc/nftables.conf", Executable: "/usr/local/bin/xnodectl", Runner: runner, RecoveryTimeout: recoveryTimeout}
		tx, err := m.Apply(ctx, "fixture-real-watchdog", protocol.FirewallPolicy{Enabled: true, Protect: true, MasterControlled: true, TCPPorts: []int{22, 443, 9443, 60001}, UDPPorts: []int{443, 9443}, Forward: forwardingPolicy()}, false)
		if err != nil {
			fail(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(tx); err != nil {
			fail(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--after-reboot" {
		if e := afterReboot(ctx, runner); e != nil {
			fail(e)
		}
		fmt.Println("Native firewall reboot restoration and uninstall recovery passed")
		return
	}
	mode := "nftables-off"
	if len(os.Args) == 3 && os.Args[1] == "--ownership" {
		mode = os.Args[2]
	}
	if err := ownershipBaseline(ctx, runner, mode); err != nil {
		fail(err)
	}
	if e := topology(ctx, runner); e != nil {
		fail(e)
	}
	if _, e := runner.Run(ctx, "nft", "add", "table", "inet", "fixture_original"); e != nil {
		fail(e)
	}
	m := &firewall.Manager{Dir: "/var/lib/x-node/firewall", ConfigPath: "/etc/nftables.conf", Executable: "/usr/local/bin/xnodectl", Runner: runner, RecoveryTimeout: recoveryTimeout}
	policy := protocol.FirewallPolicy{Enabled: true, Protect: true, MasterControlled: true, TCPPorts: []int{443, 9443}, UDPPorts: []int{443, 9443}, SSHPorts: []int{22}, Forward: forwardingPolicy()}
	pending, e := m.Apply(ctx, "fixture-rollback", policy, false)
	if e != nil {
		fail(e)
	}
	if _, e = runner.Run(ctx, "nft", "list", "table", "inet", "x_node"); e != nil {
		fail(e)
	}
	if e = m.RollbackID(ctx, pending.ID); e != nil {
		fail(e)
	}
	pending, e = m.Apply(ctx, "fixture-confirm", policy, false)
	if e != nil {
		fail(e)
	}
	if e = m.Confirm(ctx, pending.ID); e != nil {
		fail(e)
	}
	if e = ownershipChecks(ctx, runner, true); e != nil {
		fail(e)
	}
	if _, e = runner.Run(ctx, "nft", "-c", "-f", "/etc/nftables.conf"); e != nil {
		fail(e)
	}
	if e = m.RestoreFile(ctx); e != nil {
		fail(e)
	}
	if e = packetChecks(ctx, runner); e != nil {
		fail(e)
	}
	if e = liveStateChecks(ctx, m, policy); e != nil {
		fail(e)
	}
	if e = firewallControlChecks(ctx, m, policy, runner); e != nil {
		fail(e)
	}
	if e = watchdogCheck(ctx, m, policy, runner); e != nil {
		fail(e)
	}
	if e = dnsChecks(ctx, m, policy); e != nil {
		fail(e)
	}
	for _, binary := range []string{"/usr/local/bin/x-node", "/usr/local/bin/xnodectl"} {
		b, e := exec.CommandContext(ctx, binary, "--version").Output()
		if e != nil {
			fail(e)
		}
		var v struct {
			Version      string   `json:"version"`
			Capabilities []string `json:"capabilities"`
		}
		if json.Unmarshal(b, &v) != nil || v.Version == "" {
			fail(fmt.Errorf("binary metadata missing"))
		}
	}
	if _, e = runner.Run(ctx, "systemd-analyze", "verify", "/etc/systemd/system/x-node.service"); e != nil {
		fail(e)
	}
	if _, e = runner.Run(ctx, "systemctl", "start", "--no-block", "x-node.service"); e != nil {
		fail(e)
	}
	if e = waitAgentProcess(ctx, runner); e != nil {
		fail(e)
	}
	if _, e = runner.Run(ctx, "systemctl", "stop", "x-node.service"); e != nil {
		fail(e)
	}
	fmt.Println("Disposable host binary, systemd, nftables/UFW takeover, confirmation/rollback and forwarding checks passed")
}
func fail(e error) { fmt.Fprintln(os.Stderr, e.Error()); os.Exit(1) }
