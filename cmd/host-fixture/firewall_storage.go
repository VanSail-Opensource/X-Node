package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// This runs only as root inside the disposable hosted VM. A small temporary
// mount exercises real free-space admission without filling its system disk.
func firewallStorageChecks(ctx context.Context, guard *firewall.Guard, dir string, runner host.Runner) error {
	if os.Getenv("XNODE_LARGE_FIREWALL_CHECK") != "1" {
		return nil
	}
	bulk := filepath.Join(dir, "bulk")
	if err := os.MkdirAll(bulk, 0700); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "mount", "-t", "tmpfs", "-o", "size=8m,mode=0700", "xnode-disposable-full", bulk); err != nil {
		return err
	}
	mounted := true
	defer func() {
		if mounted {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_, _ = runner.Run(cleanup, "umount", bulk)
		}
	}()
	update := protocol.FirewallUpdate{SourcesOnly: true, Version: 4, SnapshotID: "vm-storage", Final: true, Sources: []protocol.FirewallSource{{ID: "vm-storage", Generation: "vm-storage", Until: time.Now().Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"9.9.9.0/24"}}}}
	if err := guard.Sync(ctx, update); err == nil {
		return fmt.Errorf("low-disk source admission unexpectedly succeeded")
	}
	if guard.Status().SourceGenerations["vm-storage"] != "" || banRemaining("banned_v4", netip.MustParseAddr("203.0.113.90")) <= 0 {
		return fmt.Errorf("low-disk admission changed current enforcement")
	}
	if _, err := runner.Run(ctx, "umount", bulk); err != nil {
		return err
	}
	mounted = false
	if err := guard.Sync(ctx, update); err != nil {
		return fmt.Errorf("source transfer did not recover after low disk: %w", err)
	}
	if guard.Status().SourceGenerations["vm-storage"] != "vm-storage" {
		return fmt.Errorf("recovered source generation was not published")
	}
	filler := filepath.Join(bulk, "fixture-capacity")
	f, err := os.OpenFile(filler, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(filler)
	truncateErr := f.Truncate(512 << 20)
	closeErr := f.Close()
	if truncateErr != nil || closeErr != nil {
		return fmt.Errorf("prepare storage-cap fixture: %w", errors.Join(truncateErr, closeErr))
	}
	update.SnapshotID = "vm-storage-cap"
	update.Sources[0].Generation = "vm-storage-rejected"
	if err = guard.Sync(ctx, update); err == nil || guard.Status().SourceGenerations["vm-storage"] != "vm-storage" {
		return fmt.Errorf("512 MiB cap replaced current source enforcement")
	}
	if err = os.Remove(filler); err != nil {
		return err
	}
	fmt.Println("Firewall low-disk recovery and 512 MiB admission cap passed")
	return guard.Sync(ctx, protocol.FirewallUpdate{SourcesOnly: true, Version: 4, SnapshotID: "vm-storage-remove", Final: true, RemoveSources: []string{"vm-storage"}})
}
