package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shirou/gopsutil/v4/common"
	gnet "github.com/shirou/gopsutil/v4/net"
)

const socketHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func fixtureProc(tb testing.TB, tables map[string]string) context.Context {
	tb.Helper()
	root := tb.TempDir()
	if err := os.Mkdir(filepath.Join(root, "net"), 0o700); err != nil {
		tb.Fatal(err)
	}
	for name, data := range tables {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(data), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	return context.WithValue(context.Background(), common.EnvKey, common.EnvMap{common.HostProcEnvKey: root})
}

func TestSocketCounts(t *testing.T) {
	row := "  0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0   0 1\n"
	ctx := fixtureProc(t, map[string]string{
		"tcp":  socketHeader + row + " \t\r\n\n" + row,
		"tcp6": socketHeader + row,
		"udp":  socketHeader + row,
		"unix": "Not an Internet socket table",
	})
	tcp, udp, err := socketCounts(ctx)
	if err != nil || tcp != 3 || udp != 1 {
		t.Fatalf("socket counts = %d TCP, %d UDP, error %v", tcp, udp, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := socketCounts(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled socket counts error = %v", err)
	}
	missing := fixtureProc(t, map[string]string{"tcp": socketHeader + row})
	if tcp, udp, err := socketCounts(missing); !errors.Is(err, os.ErrNotExist) || tcp != 0 || udp != 0 {
		t.Fatalf("missing required table gave %d TCP, %d UDP, error %v", tcp, udp, err)
	}
	empty := fixtureProc(t, map[string]string{"tcp": socketHeader + row, "udp": ""})
	if tcp, udp, err := socketCounts(empty); !errors.Is(err, io.ErrUnexpectedEOF) || tcp != 0 || udp != 0 {
		t.Fatalf("missing socket header gave %d TCP, %d UDP, error %v", tcp, udp, err)
	}
}

func BenchmarkSocketCounts(b *testing.B) {
	var rows strings.Builder
	rows.WriteString(socketHeader)
	for i := range 2000 {
		fmt.Fprintf(&rows, "  %d: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0   0 %d\n", i, 10000+i, i+1)
	}
	ctx := fixtureProc(b, map[string]string{
		"tcp":  rows.String(),
		"udp":  socketHeader,
		"unix": "Num RefCount Protocol Flags Type St Inode Path\n",
	})
	b.Run("legacy-gopsutil", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			connections, err := gnet.ConnectionsWithContext(ctx, "all")
			if err != nil || len(connections) != 2000 {
				b.Fatalf("legacy socket count = %d, error %v", len(connections), err)
			}
		}
	})
	b.Run("proc-rows", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			tcp, udp, err := socketCounts(ctx)
			if err != nil || tcp != 2000 || udp != 0 {
				b.Fatalf("socket counts = %d TCP, %d UDP, error %v", tcp, udp, err)
			}
		}
	})
}
