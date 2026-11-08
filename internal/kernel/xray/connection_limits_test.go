package xray

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestRealClientLimitIncludesIdleMuxAndTCPFlows(t *testing.T) {
	for _, mux := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%t", mux), func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					conn, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
			cfg, port := testConfig(t)
			cfg.Users[0].ConnectionLimit = 1
			registry := sessions.New()
			registry.SetUsers(cfg.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err := runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
			if mux {
				peer["mux"] = map[string]any{"enabled": true, "concurrency": 8}
			}
			client := nativeClient(t, peer)
			destination := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port))
			first, err := core.Dial(context.Background(), client, destination)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			echoRoundTrip(t, first)
			awaitMeteredTraffic(t, registry, 1, 4, 4)
			registry.SampleActivity()
			registry.SampleActivity()
			if registry.Summary().Connections[1] != 0 || registry.Summary().TotalConnections[1] != 1 {
				t.Fatal("idle stream fixture was not established")
			}
			second, err := core.Dial(context.Background(), client, destination)
			if err != nil {
				t.Fatal(err)
			}
			stop := time.AfterFunc(3*time.Second, func() { _ = second.Close() })
			_, writeErr := second.Write([]byte("echo"))
			var reply [4]byte
			readErr := writeErr
			if writeErr == nil {
				_, readErr = io.ReadFull(second, reply[:])
			}
			stop.Stop()
			_ = second.Close()
			if writeErr == nil && readErr == nil {
				t.Fatal("second logical flow bypassed idle connection limit")
			}
			if registry.Summary().Rejections["connection_limit"] == 0 {
				t.Fatal("flow failed without exercising admission")
			}
			echoRoundTrip(t, first)
			_ = first.Close()
			deadline := time.Now().Add(3 * time.Second)
			for registry.Summary().TotalConnections[1] != 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if registry.Summary().TotalConnections[1] != 0 {
				t.Fatal("closed stream retained client reservation")
			}
			fresh, err := core.Dial(context.Background(), client, destination)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			echoRoundTrip(t, fresh)
		})
	}
}

func echoRoundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	stop := time.AfterFunc(3*time.Second, func() { _ = conn.Close() })
	defer stop.Stop()
	if _, err := conn.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "echo" {
		t.Fatalf("native echo failed: %q %v", reply, err)
	}
}
