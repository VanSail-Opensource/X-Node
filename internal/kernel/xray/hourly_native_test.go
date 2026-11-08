package xray

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestRealHourlyTCPAndMuxGateAndSessionRevocation(t *testing.T) {
	for _, mux := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%t", mux), func(t *testing.T) {
			echo := echoListener(t)
			cfg, port := testConfig(t)
			registry, controller := nativeHourlyRegistry(t, &cfg)
			stopGrants := serveNativeHourlyGrants(t, controller)
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
			conn, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			checkEcho(t, conn)
			awaitMeteredTraffic(t, registry, 1, 4, 4)
			assertNativeHourlySamples(t, controller, 4)
			if registry.Summary().TotalConnections[1] != 1 {
				t.Fatal("logical hourly flow missing")
			}
			stopGrants()
			controller.SetSession("")
			if registry.Summary().TotalConnections[1] != 0 {
				t.Fatal("session fence retained native lease")
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write([]byte("late"))
			if _, err = conn.Read(make([]byte, 4)); err == nil {
				t.Fatal("session revocation retained the real native stream")
			}
			if deadline, ok := err.(net.Error); ok && deadline.Timeout() {
				t.Fatal("native stream only stopped at the test deadline")
			}
		})
	}
}

func TestRealHourlyUDPAndXUDPKeepDatagramBoundaries(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		payload := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFrom(payload)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(payload[:n], addr)
		}
	}()
	for _, mux := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%t", mux), func(t *testing.T) {
			cfg, port := testConfig(t)
			registry, controller := nativeHourlyRegistry(t, &cfg)
			serveNativeHourlyGrants(t, controller)
			runtime := New(registry)
			defer runtime.Stop()
			if err := runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
			if mux {
				peer["mux"] = map[string]any{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}
			}
			client := nativeClient(t, peer)
			packet, err := core.DialUDP(context.Background(), client)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			stop := time.AfterFunc(3*time.Second, func() { _ = packet.Close() })
			defer stop.Stop()
			for _, payload := range []string{"first", "second-datagram"} {
				if _, err = packet.WriteTo([]byte(payload), echo.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, 128)
				n, _, err := packet.ReadFrom(reply)
				if err != nil || string(reply[:n]) != payload {
					t.Fatal("hourly UDP datagram changed or fragmented", err)
				}
			}
			awaitMeteredTraffic(t, registry, 1, 20, 20)
			assertNativeHourlySamples(t, controller, 20)
		})
	}
}
