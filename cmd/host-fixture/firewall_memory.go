package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func processRSS() (uint64, error) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("invalid RSS field")
			}
			n, err := strconv.ParseUint(fields[1], 10, 64)
			return n * 1024, err
		}
	}
	return 0, fmt.Errorf("RSS measurement unavailable")
}

// The dedicated VM case measures actual process RSS, including native netlink
// work, rather than treating retained Go heap as a substitute for resident memory.
func firewallMemoryChecks(ctx context.Context, guard *firewall.Guard) error {
	if os.Getenv("XNODE_LARGE_FIREWALL_CHECK") != "1" {
		return nil
	}
	runtime.GC()
	baseline, err := processRSS()
	if err != nil {
		return err
	}
	var peak atomic.Uint64
	peak.Store(baseline)
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if rss, err := processRSS(); err == nil {
					for old := peak.Load(); rss > old; old = peak.Load() {
						if peak.CompareAndSwap(old, rss) {
							break
						}
					}
				}
			}
		}
	}()
	defer func() { close(stop); <-joined }()
	const count = 1_000_000
	until := time.Now().Add(time.Hour)
	for offset, index := 0, 0; offset < count; offset, index = offset+256, index+1 {
		prefixes := make([]string, 0, 256)
		for i := offset; i < min(offset+256, count); i++ {
			value := uint32(0x25000000) + uint32(i)*16
			prefixes = append(prefixes, fmt.Sprintf("%d.%d.%d.%d/32", value>>24, byte(value>>16), byte(value>>8), byte(value)))
		}
		chunk := protocol.FirewallUpdate{SourcesOnly: true, Version: 5, SnapshotID: "vm-million", Index: index, Final: offset+256 >= count, Sources: []protocol.FirewallSource{{ID: "vm-large", Generation: "vm-million", Until: until, RefreshSeconds: 3600, Prefixes: prefixes}}}
		if !chunk.Final {
			if err = guard.Sync(ctx, chunk); err != nil {
				return err
			}
			continue
		}
		finished := make(chan error, 1)
		go func() { finished <- guard.Sync(ctx, chunk) }()
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			<-finished
			return ctx.Err()
		case <-timer.C:
		}
		started := time.Now()
		ban := protocol.FirewallBan{Prefix: "203.0.113.91", Generation: "vm-priority", Until: until, RefreshSeconds: 3600}
		if err = guard.Update(ctx, protocol.FirewallUpdate{Version: 6, SnapshotID: "vm-priority", Bans: []protocol.FirewallBan{ban}}); err != nil {
			<-finished
			return err
		}
		if elapsed := time.Since(started); elapsed > 10*time.Second {
			<-finished
			return fmt.Errorf("dynamic delivery waited %s for source staging", elapsed)
		}
		if banRemaining("banned_v4", netip.MustParseAddr("203.0.113.91")) <= 0 {
			<-finished
			return fmt.Errorf("urgent update completed without native enforcement")
		}
		if err = <-finished; err != nil {
			return err
		}
	}
	if growth := peak.Load() - baseline; growth > 64<<20 {
		return fmt.Errorf("million-prefix RSS grew %d bytes", growth)
	}
	fmt.Printf("Million-prefix source ingestion: RSS baseline=%d peak=%d growth=%d bytes\n", baseline, peak.Load(), peak.Load()-baseline)
	if err = guard.Update(ctx, protocol.FirewallUpdate{Version: 7, SnapshotID: "vm-priority-remove", Remove: []string{"203.0.113.91"}}); err != nil {
		return err
	}
	return guard.Sync(ctx, protocol.FirewallUpdate{SourcesOnly: true, Version: 8, SnapshotID: "vm-million-remove", Final: true, RemoveSources: []string{"vm-large"}})
}
