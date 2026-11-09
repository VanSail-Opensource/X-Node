package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/VanSail-Opensource/X-Node/internal/host"
)

// Port-labelled echoes prove deterministic offsets; a random NAT range allocator
// could reach an open service but cannot consistently choose the expected port.
func rangePacketChecks(ctx context.Context, r host.Runner) error {
	for _, port := range []string{"9001", "9002", "9003"} {
		stop, err := startEcho(ctx, "xnode-target", port)
		if err != nil {
			return err
		}
		defer stop()
	}
	for _, addr := range []string{"198.18.0.1", "2001:db8:1::1"} {
		for _, network := range []string{"tcp", "udp"} {
			for offset := 0; offset < 3; offset++ {
				for _, mapping := range []struct{ source, target int }{{24500, 0}, {24600, 9001}} {
					args := []string{"netns", "exec", "xnode-client", "python3", "-c", echoProbe, addr, strconv.Itoa(mapping.source + offset), network}
					if mapping.target != 0 {
						args = append(args, "", strconv.Itoa(mapping.target+offset))
					}
					if _, err := r.Run(ctx, "ip", args...); err != nil {
						return fmt.Errorf("range %s %s:%d: %w", network, addr, mapping.source+offset, err)
					}
				}
			}
		}
	}
	return nil
}
