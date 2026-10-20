package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
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

// A oneshot without RemainAfterExit is inactive after successful completion.
// The constructed agent has no master configuration, so a started MainPID is
// sufficient here; runtime readiness is verified separately after enrollment.
func rebootReady(ctx context.Context, r host.Runner) (string, error) {
	output, err := r.Run(ctx, "systemctl", "show", "x-node-firewall.service", "--property=ActiveState,Result,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic")
	if err != nil {
		return "", err
	}
	if !completedBootRestore(string(output)) {
		return "", fmt.Errorf("confirmed firewall restore has not completed successfully")
	}
	pid, err := r.Run(ctx, "systemctl", "show", "x-node.service", "--property=MainPID", "--value")
	if err != nil {
		return "", err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(pid)), 10, 64)
	if err != nil || value == 0 {
		return "", fmt.Errorf("agent process has not started")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(boot)), err
}

func completedBootRestore(output string) bool {
	properties := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			properties[key] = strings.TrimSpace(value)
		}
	}
	start, startErr := strconv.ParseUint(properties["ExecMainStartTimestampMonotonic"], 10, 64)
	end, endErr := strconv.ParseUint(properties["ExecMainExitTimestampMonotonic"], 10, 64)
	state := properties["ActiveState"]
	return startErr == nil && endErr == nil && start > 0 && end >= start &&
		(state == "inactive" || state == "active") && properties["Result"] == "success" && properties["ExecMainStatus"] == "0"
}
