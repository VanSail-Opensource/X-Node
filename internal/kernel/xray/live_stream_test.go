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
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func TestRoutingChangesPreserveRealStreamsAndReuseMatchers(t *testing.T) {
	for _, mux := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%t", mux), func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					c, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			cfg, port := testConfig(t)
			registry := sessions.New()
			registry.SetUsers(cfg.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err = runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			instance, epoch := runtime.instance, runtime.current.Epochs["in"]
			peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
			if mux {
				peer["mux"] = map[string]any{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}
			}
			client := nativeClient(t, peer)
			conn, err := core.Dial(context.Background(), client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			check := func() {
				t.Helper()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Write([]byte("alive")); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 5)
				if _, err := io.ReadFull(conn, b); err != nil || string(b) != "alive" {
					t.Fatal("existing stream interrupted", err)
				}
			}
			check()
			for i := 0; i < 3; i++ {
				if err = runtime.Apply(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				check()
				if runtime.instance != instance || runtime.current.Epochs["in"] != epoch || runtime.Statistics().Rebuilds != 1 {
					t.Fatal("unchanged reload interrupted serving runtime")
				}
			}
			cfg = editNative(t, cfg, func(r map[string]any) {
				r["outbounds"] = append(r["outbounds"].([]any), map[string]any{"tag": "blocked", "protocol": "blackhole"})
				r["routing"] = map[string]any{"rules": []any{map[string]any{"ruleTag": "first", "type": "field", "domain": []string{"full:first.invalid"}, "outboundTag": "blocked"}}}
			})
			if err = runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			check()
			before := runtime.Statistics()
			routeContext := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.DomainAddress("first.invalid"), 443)}})
			route, routeErr := runtime.instance.GetFeature(routing.RouterType()).(routing.Router).PickRoute(routing_session.AsRoutingContext(routeContext))
			if routeErr != nil || route.GetOutboundTag() != "blocked" {
				t.Fatal("new connections did not receive published route", routeErr)
			}
			cfg = editNative(t, cfg, func(r map[string]any) {
				routing := r["routing"].(map[string]any)
				routing["rules"] = append(routing["rules"].([]any), map[string]any{"ruleTag": "second", "type": "field", "domain": []string{"full:second.invalid"}, "outboundTag": "blocked"})
			})
			if err = runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			check()
			after := runtime.Statistics()
			if runtime.instance != instance || runtime.current.Epochs["in"] != epoch || after.Rebuilds != 1 {
				t.Fatal("routing change rebuilt runtime or epoch")
			}
			if after.MatcherBuilds-before.MatcherBuilds != 1 || after.InboundBuilds != before.InboundBuilds || after.OutboundBuilds != before.OutboundBuilds {
				t.Fatalf("unchanged sections rebuilt: before=%+v after=%+v", before, after)
			}
			cfg = editNative(t, cfg, func(r map[string]any) {
				rules := r["routing"].(map[string]any)["rules"].([]any)
				rules[0], rules[1] = rules[1], rules[0]
			})
			if err = runtime.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			check()
			if runtime.Statistics().MatcherBuilds-after.MatcherBuilds != 2 {
				t.Fatal("reordered table not rebuilt")
			}
			awaitMeteredTraffic(t, registry, 1, 20, 20)
		})
	}
}
