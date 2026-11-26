//go:build !linux

package monitor

import (
	"context"

	gnet "github.com/shirou/gopsutil/v4/net"
)

func socketCounts(ctx context.Context) (tcp, udp int, err error) {
	connections, err := gnet.ConnectionsWithContext(ctx, "all")
	if err != nil {
		return 0, 0, err
	}
	for _, c := range connections {
		switch c.Type {
		case 1:
			tcp++
		case 2:
			udp++
		}
	}
	return tcp, udp, nil
}
