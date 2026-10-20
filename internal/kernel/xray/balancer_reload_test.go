package xray

import (
	"context"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func TestLiveBalancerChangesRetainPublicSelectorAndRuntime(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg = editNative(t, cfg, func(root map[string]any) {
		root["outbounds"] = append(root["outbounds"].([]any), map[string]any{"tag": "blocked", "protocol": "blackhole"})
		root["routing"] = map[string]any{"balancers": []any{map[string]any{"tag": "pool", "selector": []string{"direct"}, "strategy": map[string]any{"type": "random"}}}, "rules": []any{map[string]any{"type": "field", "domain": []string{"full:example.com"}, "balancerTag": "pool"}}}
	})
	registry := sessions.New()
	registry.SetUsers(cfg.Users)
	runtime := New(registry)
	defer runtime.Stop()
	if err := runtime.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	instance := runtime.instance
	check := func(expected string) {
		t.Helper()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)}})
		route, err := runtime.instance.GetFeature(routing.RouterType()).(routing.Router).PickRoute(routing_session.AsRoutingContext(ctx))
		if err != nil || route.GetOutboundTag() != expected {
			t.Fatal("balancer selector unavailable", err)
		}
	}
	check("direct")
	cfg = editNative(t, cfg, func(root map[string]any) {
		root["routing"].(map[string]any)["balancers"].([]any)[0].(map[string]any)["selector"] = []string{"blocked"}
	})
	if err := runtime.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	check("blocked")
	if runtime.instance != instance || runtime.Statistics().Rebuilds != 1 {
		t.Fatal("balancer edit reconstructed runtime")
	}
}
