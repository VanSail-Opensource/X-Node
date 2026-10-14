// host-fixture is only executed in a marked disposable Debian 13 VM.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if e := host.CheckDebian(); e != nil {
		fail(e)
	}
	if _, e := os.Stat("/etc/x-node-fixture-vm"); e != nil {
		fail(fmt.Errorf("host integration requires a marked disposable VM"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	runner := host.Commands{}
	m := &firewall.Manager{Dir: "/var/lib/x-node/firewall", ConfigPath: "/etc/nftables.conf", Executable: "/usr/local/bin/xnodectl", Runner: runner}
	policy := protocol.FirewallPolicy{Enabled: true, Protect: true, TCPPorts: []int{443}, UDPPorts: []int{443}, SSHPorts: []int{22}, Forward: []protocol.Forward{{Port: 24443, TargetIP: "127.0.0.1", TargetPort: 443, Network: "tcp"}}}
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
	if _, e = runner.Run(ctx, "nft", "-c", "-f", "/etc/nftables.conf"); e != nil {
		fail(e)
	}
	if e = m.RestoreFile(ctx); e != nil {
		fail(e)
	}
	if e = m.RestoreOriginal(ctx); e != nil {
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
	time.Sleep(2 * time.Second)
	status, e := runner.Run(ctx, "systemctl", "show", "x-node.service", "--property=MainPID", "--value")
	if e != nil || strings.TrimSpace(string(status)) == "0" {
		fail(fmt.Errorf("agent process did not start"))
	}
	if _, e = runner.Run(ctx, "systemctl", "stop", "x-node.service"); e != nil {
		fail(e)
	}
	fmt.Println("Debian 13 binary, systemd, nftables confirmation/rollback and forwarding checks passed")
}
func fail(e error) { fmt.Fprintln(os.Stderr, e.Error()); os.Exit(1) }
