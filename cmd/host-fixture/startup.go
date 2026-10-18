package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/host"
)

func waitAgentProcess(ctx context.Context, r host.Runner) error {
	child, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		status, err := r.Run(child, "systemctl", "show", "x-node.service", "--property=MainPID", "--value")
		if err == nil && strings.TrimSpace(string(status)) != "" && strings.TrimSpace(string(status)) != "0" {
			return nil
		}
		select {
		case <-child.Done():
			// The marked VM contains only constructed configuration/credentials.
			logs, _ := r.Run(ctx, "journalctl", "-u", "x-node-firewall.service", "-u", "x-node.service", "--no-pager", "-n", "40")
			return fmt.Errorf("agent process did not start after firewall dependencies: %s", logs)
		case <-tick.C:
		}
	}
}
