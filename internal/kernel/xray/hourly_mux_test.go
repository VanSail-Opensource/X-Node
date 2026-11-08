package xray

import (
	"context"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestRealHourlyMuxNormalCompletionPreservesIdleSibling(t *testing.T) {
	echo := echoListener(t)
	cfg, port := testConfig(t)
	registry, controller := nativeHourlyRegistry(t, &cfg)
	stopGrants := serveNativeHourlyGrants(t, controller)
	runtime := New(registry)
	defer runtime.Stop()
	if err := runtime.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}, "mux": map[string]any{"enabled": true, "concurrency": 8}}
	client := nativeClient(t, peer)
	dial := func() net.Conn {
		t.Helper()
		conn, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	first := dial()
	echoRoundTrip(t, first)
	sibling := dial()
	echoRoundTrip(t, sibling)
	awaitMeteredTraffic(t, registry, 1, 8, 8)
	if registry.Summary().TotalConnections[1] != 2 {
		t.Fatal("mux fixture did not establish two logical flows")
	}
	_ = first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for registry.Summary().TotalConnections[1] != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if registry.Summary().TotalConnections[1] != 1 {
		t.Fatal("normal mux flow close terminated its sibling")
	}
	echoRoundTrip(t, sibling)
	awaitMeteredTraffic(t, registry, 1, 12, 12)
	assertNativeHourlySamples(t, controller, 12)
	stopGrants()
	defer boundHourlyIO(t, sibling)()
	controller.ApplyAuthorization(100, 100, nil)
	if _, err := sibling.Read(make([]byte, 1)); err == nil {
		t.Fatal("authorization revoke left the idle authenticated mux transport readable")
	}
}
