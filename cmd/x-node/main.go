package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/agent"
	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	"github.com/xtls/xray-core/core"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"
var buildTime = "unknown"
var commit = "unknown"

func main() {
	path := flag.String("config", "/etc/x-node/bootstrap.json", "connection bootstrap JSON")
	dir := flag.String("state-dir", "/var/lib/x-node", "private state directory")
	show := flag.Bool("version", false, "print build metadata")
	check := flag.String("check-config", "", "validate remote configuration JSON shape")
	flag.Parse()
	if *show {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "build_time": buildTime, "commit": commit, "xray": "v" + core.Version(), "capabilities": agent.Capabilities})
		return
	}
	if *check != "" {
		b, e := os.ReadFile(*check)
		if e != nil {
			fail("cannot read remote configuration")
		}
		if _, e = protocol.ParseConfig(b); e != nil {
			fail(e.Error())
		}
		fmt.Println("Remote configuration shape is valid; TLS material and native Xray are validated during activation.")
		return
	}
	if e := host.CheckRequirements(); e != nil {
		fail(e.Error())
	}
	bootstrap, e := config.Load(*path)
	if e != nil {
		fail(e.Error())
	}
	logs := nlog.NewStream(os.Stdout)
	logs.Secrets(bootstrap.Token)
	nlog.Init(logs, slog.LevelInfo, false)
	client := transport.New(bootstrap.MasterURL, bootstrap.Token)
	process, e := agent.New(*dir, version, client, logs)
	if e != nil {
		fail("private state cannot be loaded")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e = process.Run(ctx); e != nil {
		fail("agent shutdown could not persist traffic")
	}
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
