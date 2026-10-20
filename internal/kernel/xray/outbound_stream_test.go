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

func echoListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener
}

func checkEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "data" {
		t.Fatal("echo failed", err)
	}
}

func TestOutboundReplacementClosesOnlyAffectedRealFlow(t *testing.T) {
	a, b := echoListener(t), echoListener(t)
	cfg, port := testConfig(t)
	cfg = editNative(t, cfg, func(r map[string]any) {
		out := map[string]any{"tag": "alternate", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}
		r["outbounds"] = append(r["outbounds"].([]any), out)
		r["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "port": fmt.Sprint(a.Addr().(*net.TCPAddr).Port), "outboundTag": "alternate"}}}
	})
	registry := sessions.New()
	registry.SetUsers(cfg.Users)
	runtime := New(registry)
	defer runtime.Stop()
	if err := runtime.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	instance := runtime.instance
	peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
	client := nativeClient(t, peer)
	dial := func(target net.Listener) net.Conn {
		t.Helper()
		conn, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(target.Addr().(*net.TCPAddr).Port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	affected, unchanged := dial(a), dial(b)
	checkEcho(t, affected)
	checkEcho(t, unchanged)
	cfg = editNative(t, cfg, func(r map[string]any) {
		r["outbounds"].([]any)[1].(map[string]any)["settings"].(map[string]any)["domainStrategy"] = "UseIPv4"
	})
	if err := runtime.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if runtime.instance != instance {
		t.Fatal("outbound replacement rebuilt runtime")
	}
	checkEcho(t, unchanged)
	_ = affected.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = affected.Write([]byte("obsolete"))
	if _, err := affected.Read(make([]byte, 1)); err == nil {
		t.Fatal("replaced outbound kept obsolete flow")
	}
	checkEcho(t, dial(a))
}

func TestRoutingUpdatesKeepRealUDPAssociation(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 1024)
		for {
			n, addr, err := echo.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(b[:n], addr)
		}
	}()
	for _, mux := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%t", mux), func(t *testing.T) {
			cfg, port := testConfig(t)
			registry := sessions.New()
			registry.SetUsers(cfg.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err := runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			instance := runtime.instance
			peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
			if mux {
				peer["mux"] = map[string]any{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}
			}
			client := nativeClient(t, peer)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			packet, err := core.DialUDP(ctx, client)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			check := func() {
				t.Helper()
				if _, err := packet.WriteTo([]byte("udp"), echo.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 32)
				n, _, err := packet.ReadFrom(b)
				if err != nil || string(b[:n]) != "udp" {
					t.Fatal("UDP association interrupted", err)
				}
			}
			check()
			cfg = editNative(t, cfg, func(r map[string]any) {
				r["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "domain": []string{"full:unrelated.invalid"}, "outboundTag": "direct"}}}
			})
			if err := runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			check()
			if runtime.instance != instance {
				t.Fatal("UDP update restarted runtime")
			}
		})
	}
}
