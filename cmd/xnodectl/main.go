package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"github.com/VanSail-Opensource/X-Node/internal/update"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var version = "dev"
var buildTime = "unknown"
var commit = "unknown"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		fmt.Println("xnodectl configure|status|service|upgrade|rollback|uninstall")
		return nil
	}
	if args[0] == "--version" || args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version, "build_time": buildTime, "commit": commit})
	}
	if e := host.CheckDebian(); e != nil {
		return e
	}
	ctx := context.Background()
	runner := host.Commands{}
	switch args[0] {
	case "configure":
		flags := flag.NewFlagSet("configure", flag.ContinueOnError)
		url := flags.String("master-url", "", "master WSS URL")
		path := flags.String("config", "/etc/x-node/bootstrap.json", "bootstrap path")
		stdin := flags.Bool("token-stdin", false, "read token from standard input")
		if e := flags.Parse(args[1:]); e != nil {
			return e
		}
		if !*stdin {
			return errors.New("use --token-stdin to keep the token out of process arguments")
		}
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 8193))
		if e != nil || len(b) > 8192 {
			return errors.New("invalid token input")
		}
		bootstrap := config.Bootstrap{MasterURL: *url, Token: strings.TrimSpace(string(b))}
		if e = config.Validate(bootstrap); e != nil {
			return e
		}
		data, _ := json.Marshal(bootstrap)
		if e = state.AtomicWrite(*path, data, 0600); e != nil {
			return e
		}
		if _, e = config.Load(*path); e != nil {
			return e
		}
		fmt.Println("Connection bootstrap configured.")
		return nil
	case "status":
		path := "/var/lib/x-node/status.json"
		if len(args) > 1 {
			return errors.New("status takes no arguments")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return errors.New("agent status is not available")
		}
		_, e = os.Stdout.Write(append(b, '\n'))
		return e
	case "service":
		if len(args) != 2 {
			return errors.New("service requires start, stop, restart, enable, disable, status or logs")
		}
		action := args[1]
		switch action {
		case "start", "stop", "restart", "enable", "disable", "status":
			b, e := runner.Run(ctx, "systemctl", action, "x-node.service")
			if len(b) > 0 {
				_, _ = os.Stdout.Write(b)
			}
			return e
		case "logs":
			b, e := runner.Run(ctx, "journalctl", "-u", "x-node.service", "--no-pager", "-n", "100")
			if len(b) > 0 {
				_, _ = os.Stdout.Write(b)
			}
			return e
		default:
			return errors.New("unknown service action")
		}
	case "upgrade":
		flags := flag.NewFlagSet("upgrade", flag.ContinueOnError)
		target := flags.String("version", "", "stable version tag")
		check := flags.Bool("check", false, "only check for a new release")
		if e := flags.Parse(args[1:]); e != nil {
			return e
		}
		m := update.New("/var/lib/x-node/updates", version, runner)
		if *check {
			result, e := m.Check(ctx, *target)
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		result, e := m.Install(ctx, state.ID(), *target, func(data any) { _ = json.NewEncoder(os.Stdout).Encode(data) })
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "rollback":
		return update.New("/var/lib/x-node/updates", version, runner).Rollback(ctx)
	case "upgrade-rollback":
		flags := flag.NewFlagSet("upgrade-rollback", flag.ContinueOnError)
		dir := flags.String("state-dir", "/var/lib/x-node/updates", "upgrade state directory")
		if e := flags.Parse(args[1:]); e != nil {
			return e
		}
		return update.New(*dir, version, runner).RollbackPending(ctx)
	case "firewall-rollback", "firewall-restore":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		dir := flags.String("state-dir", "/var/lib/x-node/firewall", "firewall state directory")
		requestID := flags.String("request-id", "", "specific firewall transaction")
		if e := flags.Parse(args[1:]); e != nil {
			return e
		}
		m := &firewall.Manager{Dir: *dir, ConfigPath: "/etc/nftables.conf", Executable: "/usr/local/bin/xnodectl", Runner: runner}
		if args[0] == "firewall-restore" {
			return m.RestoreFile(ctx)
		}
		return m.RollbackID(ctx, *requestID)
	case "uninstall":
		flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
		purge := flags.Bool("purge", false, "also remove bootstrap and private state")
		if e := flags.Parse(args[1:]); e != nil {
			return e
		}
		_, _ = runner.Run(ctx, "systemctl", "disable", "--now", "x-node.service")
		_, _ = runner.Run(ctx, "systemctl", "disable", "x-node-firewall.service")
		firewallManager := &firewall.Manager{Dir: "/var/lib/x-node/firewall", ConfigPath: "/etc/nftables.conf", Executable: "/usr/local/bin/xnodectl", Runner: runner}
		if e := firewallManager.RestoreOriginal(ctx); e != nil {
			return e
		}
		for _, path := range []string{"/etc/systemd/system/x-node.service", "/etc/systemd/system/x-node-firewall.service", "/usr/local/bin/x-node", "/usr/local/bin/xnodectl"} {
			if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
		if *purge {
			for _, path := range []string{"/etc/x-node", "/var/lib/x-node"} {
				clean := filepath.Clean(path)
				if clean != path || clean == "/" {
					return errors.New("unsafe uninstall path")
				}
				if e := os.RemoveAll(clean); e != nil {
					return e
				}
			}
		}
		_, e := runner.Run(ctx, "systemctl", "daemon-reload")
		return e
	default:
		return errors.New("unknown xnodectl command")
	}
}
