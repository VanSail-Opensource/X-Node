package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

const additionalInboundUser = "550e8400-e29b-41d4-a716-446655440055"

func dialInboundEcho(t *testing.T, port int, id string, echo net.Listener) net.Conn {
	t.Helper()
	peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{
		"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": id, "encryption": "none"}}}},
	}}
	conn, err := core.Dial(context.Background(), nativeClient(t, peer), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestInboundProxySwapKeepsServingAndAcceptsNewAccounts(t *testing.T) {
	ctx := context.Background()
	echo := echoListener(t)
	config, port := testConfig(t)
	registry := sessions.New()
	registry.SetUsers(config.Users)
	r := New(registry)
	t.Cleanup(r.Stop)
	if err := r.Apply(ctx, config); err != nil {
		t.Fatal(err)
	}
	old := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, old)
	instance := r.instance
	updated := editNative(t, config, func(root map[string]any) {
		in := root["inbounds"].([]any)[0].(map[string]any)
		in["settings"].(map[string]any)["fallbacks"] = []any{map[string]any{"dest": echo.Addr().String()}}
	})
	updated.Users = append(updated.Users, protocol.User{ID: 42, UUID: additionalInboundUser, InboundTags: []string{"in"}})
	registry.SetUsers(updated.Users)
	if err := r.Apply(ctx, updated); err != nil {
		t.Fatal(err)
	}
	if r.instance != instance || !r.Ready() || r.stats.ListenerGapMicros != 0 {
		t.Fatal("receiver restarted during same-endpoint proxy update")
	}
	checkEcho(t, old)
	checkEcho(t, dialInboundEcho(t, port, testUUID, echo))
	checkEcho(t, dialInboundEcho(t, port, additionalInboundUser, echo))
}

func TestInboundStagingFailureLeavesOldAndNewConnectionsServing(t *testing.T) {
	ctx := context.Background()
	echo := echoListener(t)
	config, port := testConfig(t)
	registry := sessions.New()
	registry.SetUsers(config.Users)
	r := New(registry)
	t.Cleanup(r.Stop)
	if err := r.Apply(ctx, config); err != nil {
		t.Fatal(err)
	}
	old := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, old)
	reserve := func() net.Listener {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	available := reserve()
	newPort := available.Addr().(*net.TCPAddr).Port
	_ = available.Close()
	occupied := reserve()
	t.Cleanup(func() { _ = occupied.Close() })
	blocked := occupied.Addr().(*net.TCPAddr).Port
	updated := editNative(t, config, func(root map[string]any) {
		for _, endpoint := range []struct {
			tag  string
			port int
		}{{"available", newPort}, {"occupied", blocked}} {
			root["inbounds"] = append(root["inbounds"].([]any), map[string]any{
				"tag": endpoint.tag, "listen": "127.0.0.1", "port": endpoint.port, "protocol": "vless", "settings": map[string]any{"decryption": "none"},
			})
		}
	})
	updated.Users = append(updated.Users, protocol.User{ID: 42, UUID: additionalInboundUser, InboundTags: []string{"available"}})
	registry.SetUsers(updated.Users)
	if err := r.Apply(ctx, updated); err == nil {
		t.Fatal("occupied listener accepted")
	}
	checkEcho(t, old)
	checkEcho(t, dialInboundEcho(t, port, testUUID, echo))
	if probe, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", newPort)); err != nil {
		t.Fatal("failed activation leaked staged listener", err)
	} else {
		_ = probe.Close()
	}
	_ = occupied.Close()
	if err := r.Apply(ctx, updated); err != nil {
		t.Fatal(err)
	}
	checkEcho(t, old)
	checkEcho(t, dialInboundEcho(t, newPort, additionalInboundUser, echo))
	broken := editNative(t, updated, func(root map[string]any) {
		root["inbounds"].([]any)[0].(map[string]any)["port"] = blocked
	})
	if err := r.Apply(ctx, broken); !errors.Is(err, ErrReloadUnsupported) {
		t.Fatalf("receiver edit must decline live without stopping the listener: %v", err)
	}
	checkEcho(t, old)
	checkEcho(t, dialInboundEcho(t, port, testUUID, echo))
}
