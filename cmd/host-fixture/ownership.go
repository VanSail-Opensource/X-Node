package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/host"
)

func checkDisposableHost() error {
	if err := host.CheckLinux(); err != nil {
		return err
	}
	marker, err := os.ReadFile("/etc/x-node-fixture-vm")
	if err != nil || strings.TrimSpace(string(marker)) != "disposable" {
		return fmt.Errorf("host integration requires a marked disposable VM")
	}
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = strings.Trim(value, "\"'")
		}
	}
	if fields["ID"] == "debian" && fields["VERSION_ID"] == "13" || fields["ID"] == "ubuntu" && fields["VERSION_ID"] == "24.04" {
		return nil
	}
	return fmt.Errorf("host fixture requires disposable Debian 13 or Ubuntu 24.04")
}

func ownershipBaseline(ctx context.Context, r host.Runner, mode string) error {
	if mode != "nftables-on" && mode != "nftables-off" && mode != "ufw-on" {
		return fmt.Errorf("unsupported host ownership fixture")
	}
	if _, err := r.Run(ctx, "systemctl", "disable", "--now", "nftables.service"); err != nil {
		return err
	}
	if mode == "nftables-on" {
		if err := os.WriteFile("/etc/nftables.conf", []byte("table inet fixture_service_boot {}\n"), 0600); err != nil {
			return err
		}
		if _, err := r.Run(ctx, "systemctl", "enable", "--now", "nftables.service"); err != nil {
			return err
		}
	}
	if mode == "ufw-on" {
		if _, err := r.Run(ctx, "systemctl", "stop", "ufw.service"); err != nil {
			return err
		}
		// CLI enforcement with an inactive oneshot catches service-only takeover.
		for _, args := range [][]string{{"allow", "22/tcp"}, {"--force", "enable"}} {
			if _, err := r.Run(ctx, "ufw", args...); err != nil {
				return err
			}
		}
	}
	return os.WriteFile("/var/lib/x-node/fixture-ownership", []byte(mode), 0600)
}

func ownershipChecks(ctx context.Context, r host.Runner, managed bool) error {
	raw, err := os.ReadFile("/var/lib/x-node/fixture-ownership")
	if err != nil {
		return err
	}
	mode := string(raw)
	enabled, _ := r.Run(ctx, "systemctl", "is-enabled", "nftables.service")
	active, _ := r.Run(ctx, "systemctl", "is-active", "nftables.service")
	if managed || mode == "nftables-on" {
		if strings.TrimSpace(string(enabled)) != "enabled" || strings.TrimSpace(string(active)) != "active" {
			return fmt.Errorf("nftables service was not enabled: %s %s", enabled, active)
		}
	} else if strings.TrimSpace(string(enabled)) != "disabled" || strings.TrimSpace(string(active)) != "inactive" {
		return fmt.Errorf("previous disabled nftables service was not restored: %s %s", enabled, active)
	}
	if mode == "ufw-on" {
		enabled, _ = r.Run(ctx, "systemctl", "is-enabled", "ufw.service")
		status, err := r.Run(ctx, "ufw", "status")
		if err != nil {
			return err
		}
		if managed {
			if strings.TrimSpace(string(enabled)) != "masked" || !strings.Contains(string(status), "Status: inactive") {
				return fmt.Errorf("UFW retained competing ownership: %s %s", enabled, status)
			}
		} else if strings.TrimSpace(string(enabled)) != "enabled" || !strings.Contains(string(status), "Status: active") {
			return fmt.Errorf("previous UFW ownership was not restored: %s %s", enabled, status)
		}
	}
	return nil
}
