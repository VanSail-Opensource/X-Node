package xray

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestMalformedXHTTPSettingsPreserveServingListenerAndAccountedStreams(t *testing.T) {
	echo := echoListener(t)
	config, port := testConfig(t)
	config = editNative(t, config, func(root map[string]any) {
		inbound := root["inbounds"].([]any)[0].(map[string]any)
		inbound["streamSettings"] = map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{
			"path": "/stream", "h2Params": map[string]any{"MaxConcurrentStreams": 32},
		}}
	})
	registry := sessions.New()
	registry.SetUsers(config.Users)
	runtime := New(registry)
	defer runtime.Stop()
	if err := runtime.Apply(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	instance, epoch := runtime.instance, runtime.current.Epochs["in"]
	peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{
		"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}},
	}, "streamSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/stream"}}}
	client := nativeClient(t, peer)
	destination := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port))
	connection, err := core.Dial(context.Background(), client, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	checkEcho(t, connection)
	awaitMeteredTraffic(t, registry, 1, 4, 4)
	before := registry.Counters()[1]
	badH2 := map[string]any{"MaxConcurrentStreams": "invalid"}
	for index, settings := range []map[string]any{
		{"h2Params": badH2},
		{"extra": map[string]any{"h2Params": badH2}},
		{"extra": map[string]any{"downloadSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"h2Params": badH2}}}},
		{"downloadSettings": map[string]any{"network": "xhttp", "port": 443}},
		{"downloadSettings": map[string]any{"address": "127.0.0.1", "port": 443, "network": "tcp"}},
	} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			invalid := editNative(t, config, func(root map[string]any) {
				inbound := root["inbounds"].([]any)[0].(map[string]any)
				stream := inbound["streamSettings"].(map[string]any)
				stream["xhttpSettings"] = settings
			})
			if err := runtime.Apply(context.Background(), invalid, true); err == nil {
				t.Fatal("malformed HTTP/2 candidate reached activation")
			}
			if !runtime.Ready() || runtime.instance != instance || runtime.current.Epochs["in"] != epoch {
				t.Fatal("rejected HTTP/2 candidate disturbed serving listener")
			}
			checkEcho(t, connection)
			if counts := registry.Counters()[1]; counts[0] < before[0] || counts[1] < before[1] {
				t.Fatal("rejected candidate erased accounted traffic")
			}
		})
	}
	fresh, err := core.Dial(context.Background(), client, destination)
	if err != nil {
		t.Fatal("serving listener no longer accepts fresh streams", err)
	}
	defer fresh.Close()
	checkEcho(t, fresh)
}
