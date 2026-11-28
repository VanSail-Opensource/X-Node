package xray

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func memberRouteTestVLESS(tag string, port int, uuid string) map[string]any {
	return map[string]any{
		"tag": tag, "protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port,
			"users": []any{map[string]any{"id": uuid, "encryption": "none"}},
		}}},
	}
}

func memberRouteTestRelay(t *testing.T, reply, uuid string) int {
	t.Helper()
	target := serveTCP(t, func(c net.Conn) {
		var payload [4]byte
		for {
			if _, err := io.ReadFull(c, payload[:]); err != nil {
				return
			}
			if _, err := io.WriteString(c, reply); err != nil {
				return
			}
		}
	})
	cfg, port := testConfig(t)
	cfg.Users[0].UUID = uuid
	cfg = editNative(t, cfg, func(root map[string]any) {
		out := root["outbounds"].([]any)[0].(map[string]any)
		out["settings"].(map[string]any)["redirect"] = target.Addr().String()
	})
	registry := sessions.New()
	registry.SetUsers(cfg.Users)
	runtime := New(registry)
	t.Cleanup(runtime.Stop)
	if err := runtime.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	return port
}

type testMemberRoute struct {
	tag        string
	relayPort  int
	targetPort int
	uuid       string
	disableMux bool
}

func memberRouteTestConfig(t *testing.T, base protocol.Config, routes ...testMemberRoute) protocol.Config {
	t.Helper()
	cfg := editNative(t, base, func(root map[string]any) {
		rules := make([]any, 0, len(routes))
		for _, route := range routes {
			out := memberRouteTestVLESS(route.tag, route.relayPort, route.uuid)
			if route.disableMux {
				out["mux"] = map[string]any{"enabled": false}
			}
			root["outbounds"] = append(root["outbounds"].([]any), out)
			rules = append(rules, map[string]any{
				"type": "field", "ruleTag": route.tag, "port": fmt.Sprint(route.targetPort),
				"user":        []string{fmt.Sprintf(`regexp:^user@%d:[0-9a-f]{32}@[0-9a-f]{24}$`, base.Users[0].ID)},
				"inboundTag":  []string{"in"},
				"outboundTag": route.tag,
			})
		}
		if len(rules) != 0 {
			root["routing"] = map[string]any{"rules": rules}
		}
	})
	for _, route := range routes {
		cfg.MemberOutbounds = append(cfg.MemberOutbounds, route.tag)
	}
	return cfg
}

func TestMemberRouteReloadKeepsServingSourceTraffic(t *testing.T) {
	const (
		oldUUID   = "550e8400-e29b-41d4-a716-446655440031"
		newUUID   = "550e8400-e29b-41d4-a716-446655440032"
		otherUUID = "550e8400-e29b-41d4-a716-446655440033"
	)
	relayA := memberRouteTestRelay(t, "old!", oldUUID)
	relayB := memberRouteTestRelay(t, "new!", newUUID)
	target := echoListener(t).Addr().(*net.TCPAddr).Port
	secondTarget := echoListener(t).Addr().(*net.TCPAddr).Port
	base, port := testConfig(t)
	base.Users = append(base.Users, protocol.User{ID: 2, UUID: otherUUID, InboundTags: []string{"in"}})

	registry := sessions.New()
	registry.SetUsers(base.Users)
	runtime := New(registry)
	t.Cleanup(runtime.Stop)
	if err := runtime.Apply(t.Context(), base); err != nil {
		t.Fatal(err)
	}
	instance, epoch := runtime.instance, runtime.current.Epochs["in"]
	owner := nativeClient(t, memberRouteTestVLESS("peer", port, testUUID))
	other := nativeClient(t, memberRouteTestVLESS("peer", port, otherUUID))
	dial := func(client *core.Instance, target int) net.Conn {
		t.Helper()
		conn, err := core.Dial(t.Context(), client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(target)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	checkFresh := func(client *core.Instance, target int, expected string) {
		t.Helper()
		conn := dial(client, target)
		defer conn.Close()
		checkResponse(t, conn, expected)
	}
	keep := dial(other, target)
	checkEcho(t, keep)
	apply := func(name string, routes ...testMemberRoute) {
		t.Helper()
		// Kernel-only fixture: test transit endpoints are deliberately on
		// loopback. The agent's separate admission policy requires public IPs.
		if err := runtime.Apply(t.Context(), memberRouteTestConfig(t, base, routes...)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		stats := runtime.Statistics()
		if runtime.instance != instance || runtime.current.Epochs["in"] != epoch ||
			stats.Rebuilds != 1 || stats.LastMode != "live" || !runtime.Ready() {
			t.Fatalf("%s rebuilt or stopped the serving runtime: %+v", name, stats)
		}
		checkEcho(t, keep)
		checkFresh(other, target, "data")
	}

	// Explicitly disabled mux is a valid shape from Carpool's endpoint editor.
	old := testMemberRoute{tag: "member-route-1", relayPort: relayA, targetPort: target, uuid: oldUUID, disableMux: true}
	edited := testMemberRoute{tag: old.tag, relayPort: relayB, targetPort: target, uuid: newUUID, disableMux: true}
	added := testMemberRoute{tag: "member-route-2", relayPort: relayA, targetPort: secondTarget, uuid: oldUUID}

	apply("first route", old)
	oldStream := dial(owner, target)
	checkResponse(t, oldStream, "old!")

	// A Carpool edit first removes the old graph, then applies all desired
	// routes, including the edited route reusing its stable outbound tag.
	apply("revoke old graph")
	checkFresh(owner, target, "data")
	checkResponse(t, oldStream, "old!")
	apply("apply edited and newly added routes", edited, added)
	checkFresh(owner, target, "new!")
	checkFresh(owner, secondTarget, "old!")
	checkResponse(t, oldStream, "old!")

	newStream := dial(owner, target)
	checkResponse(t, newStream, "new!")
	apply("remove one route and restore an edited route", old)
	checkFresh(owner, secondTarget, "data")
	checkFresh(owner, target, "old!")
	checkResponse(t, newStream, "new!")
}

func TestRemovingUnmarkedRoutedOutboundRemainsBlocked(t *testing.T) {
	base, _ := testConfig(t)
	old := memberRouteTestConfig(t, base, testMemberRoute{
		tag: "administrator-ob", relayPort: 443, targetPort: 8080, uuid: testUUID,
	})
	old.MemberOutbounds = nil
	active, err := Prepare(old)
	if err != nil {
		t.Fatal(err)
	}
	next, err := PrepareCached(base, active)
	if err != nil {
		t.Fatal(err)
	}
	if blocker := outboundReloadBlocker(active, next); blocker == "" {
		t.Fatal("routed administrator outbound removal bypassed the hot reload guard")
	}
}

func TestMemberRouteRemovalKeepsNativeServiceAndBalancerBarriers(t *testing.T) {
	base, _ := testConfig(t)
	old := memberRouteTestConfig(t, base, testMemberRoute{
		tag: "member-route-1", relayPort: 443, targetPort: 8080, uuid: testUUID,
	})
	for _, test := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"native API", func(root map[string]any) {
			root["api"] = map[string]any{"tag": "api", "services": []string{"StatsService"}}
		}},
		{"native balancer", func(root map[string]any) {
			root["routing"].(map[string]any)["balancers"] = []any{
				map[string]any{"tag": "members", "selector": []string{"member-route"}},
			}
		}},
		{"active native mux", func(root map[string]any) {
			root["outbounds"].([]any)[1].(map[string]any)["MuX"] = map[string]any{"Enabled": true}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			active, err := Prepare(editNative(t, old, test.edit))
			if err != nil {
				t.Fatal(err)
			}
			next, err := PrepareCached(base, active)
			if err != nil {
				t.Fatal(err)
			}
			if blocker := outboundReloadBlocker(active, next); blocker == "" {
				t.Fatal("indirectly selected or active mux outbound removal was accepted as an ordinary field rule")
			}
		})
	}
}

func TestOutboundReloadMuxMatchesNativeJSON(t *testing.T) {
	for _, test := range []struct {
		name    string
		out     string
		blocked bool
	}{
		{"absent", `{}`, false},
		{"null", `{"mux":null}`, false},
		{"default disabled", `{"mux":{}}`, false},
		{"disabled", `{"mux":{"enabled":false,"concurrency":8}}`, false},
		{"case-insensitive disabled", `{"MuX":{"Enabled":false}}`, false},
		{"case-insensitive enabled", `{"MuX":{"Enabled":true}}`, true},
		{"invalid config shape", `{"mux":false}`, true},
		{"invalid enabled type", `{"mux":{"enabled":"false"}}`, true},
		{"invalid UDP policy", `{"mux":{"enabled":false,"xudpProxyUDP443":"invalid"}}`, true},
		{"ambiguous config", `{"Mux":{"enabled":true},"mux":null}`, true},
		{"ambiguous flag", `{"mux":{"Enabled":true,"enabled":false}}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var native map[string]any
			if err := json.Unmarshal([]byte(test.out), &native); err != nil {
				t.Fatal(err)
			}
			if blocked := unsafeOutbound(native, nil); blocked != test.blocked {
				t.Fatalf("blocked=%v, want %v", blocked, test.blocked)
			}
		})
	}
}
