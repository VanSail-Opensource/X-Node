package xray

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestRealHourlyPaidBoundaryInterruptsIdleNativeReader(t *testing.T) {
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
	client := nativeClient(t, peer)
	conn, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	checkEcho(t, conn)
	awaitMeteredTraffic(t, registry, 1, 4, 4)
	stopGrants()
	updated := protocol.Clone(cfg.Users[0])
	boundary := time.Now().Add(100 * time.Millisecond)
	updated.ValidUntil = &boundary
	registry.SetUsers([]protocol.User{updated})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("paid boundary retained idle native access")
	}
	if deadline, ok := err.(net.Error); ok && deadline.Timeout() {
		t.Fatal("idle native stream survived until the test deadline")
	}
	if registry.Summary().TotalConnections[1] != 0 {
		t.Fatal("paid boundary retained logical admission")
	}
	assertNativeHourlySamples(t, controller, 4)
}
