//go:build linux

package monitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	gnet "github.com/shirou/gopsutil/v4/net"
)

func TestProcSocketCounts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOST_PROC", root)
	netDir := filepath.Join(root, "net")
	if err := os.Mkdir(netDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, rows := range map[string]string{
		"tcp":  "header\n  1: data\n  \t\n  2: data\n",
		"tcp6": "header\n  1: data\n",
		"udp":  "header\n  1: data\n",
		"unix": "header\n not an IP socket\n",
	} {
		if err := os.WriteFile(filepath.Join(netDir, name), []byte(rows), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tcp, udp, err := socketCounts(context.Background())
	if err != nil || tcp != 3 || udp != 1 {
		t.Fatalf("got tcp=%d udp=%d err=%v, want tcp=3 udp=1", tcp, udp, err)
	}
	if err := os.Remove(filepath.Join(netDir, "udp")); err != nil {
		t.Fatal(err)
	}
	_, _, err = socketCounts(context.Background())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing IPv4 table: got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = socketCounts(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read: got %v", err)
	}
}

func BenchmarkSocketCountNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := socketCounts(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSocketCountOld(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := gnet.ConnectionsWithContext(context.Background(), "all"); err != nil {
			b.Fatal(err)
		}
	}
}
