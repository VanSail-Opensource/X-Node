package xray

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

type blockedPortRouteContext struct {
	routing.Context
	entered chan struct{}
	resume  chan struct{}
}

func (c blockedPortRouteContext) GetTargetPort() net.Port {
	close(c.entered)
	<-c.resume
	return 443
}

func (blockedPortRouteContext) GetSkipDNSResolve() bool { return true }

func TestMemberOutboundRetirementPinsEarlierRoutingDecision(t *testing.T) {
	cfg, _ := testConfig(t)
	const tag = "member-retirement"
	withMember := editNative(t, cfg, func(root map[string]any) {
		root["outbounds"] = append(root["outbounds"].([]any), map[string]any{
			"tag": tag, "protocol": "socks",
			"settings": map[string]any{"servers": []any{map[string]any{"address": "8.8.8.8", "port": 1080}}},
		})
		root["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "port": "443", "outboundTag": tag}}}
	})
	withMember.MemberOutbounds = []string{tag}

	r := New(sessions.New())
	t.Cleanup(r.Stop)
	if err := r.Apply(t.Context(), withMember); err != nil {
		t.Fatal(err)
	}
	router := r.instance.GetFeature(routing.RouterType()).(*reloadableRouter)
	manager := r.instance.GetFeature(outbound.ManagerType()).(*managedManager)
	dispatcher, ok := r.instance.GetFeature(routing.DispatcherType()).(*routeDispatcher)
	if !ok || dispatcher.picker != router {
		t.Fatal("serving dispatcher does not use pinned route selections")
	}
	old := manager.GetHandler(tag)
	if old == nil {
		t.Fatal("member outbound was not installed")
	}

	ctx := blockedPortRouteContext{entered: make(chan struct{}), resume: make(chan struct{})}
	defer func() {
		select {
		case <-ctx.resume:
		default:
			close(ctx.resume)
		}
	}()
	type result struct {
		route   routing.Route
		handler outbound.Handler
		err     error
	}
	done := make(chan result, 1)
	go func() {
		route, handler, err := router.PickRouteAndHandler(ctx)
		done <- result{route, handler, err}
	}()
	select {
	case <-ctx.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("route matcher did not start")
	}

	// Include the rule-first sequence. That previously put the tag in
	// process-lifetime route history and blocked its later retirement.
	withoutRule := editNative(t, withMember, func(root map[string]any) { delete(root, "routing") })
	if err := r.Apply(t.Context(), withoutRule); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if manager.GetHandler(tag) != nil {
		t.Fatal("retired handler still visible to new lookups")
	}
	if err := r.Apply(t.Context(), withMember); err != nil {
		t.Fatal(err)
	}
	if replacement := manager.GetHandler(tag); replacement == nil || replacement == old {
		t.Fatal("new routing generation did not publish a fresh handler")
	}

	close(ctx.resume)
	select {
	case got := <-done:
		if got.err != nil || got.route == nil || got.route.GetOutboundTag() != tag || got.handler != old {
			t.Fatalf("old decision lost its handler across two publications: %+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("route matcher did not finish")
	}
}

func TestDisjointNativeSelectorsDoNotBlockMemberRouteRetirement(t *testing.T) {
	const tag = "member-route-1"
	base, _ := testConfig(t)
	old := memberRouteTestConfig(t, base, testMemberRoute{tag: tag, relayPort: 1080, targetPort: 8080, uuid: testUUID})
	for _, selector := range []struct {
		prefix string
		allow  bool
	}{
		{"other-outbound", true},
		{"member-route", false},
		{"", false},
	} {
		t.Run(selector.prefix, func(t *testing.T) {
			withSelectors := func(c protocol.Config) protocol.Config {
				return editNative(t, c, func(root map[string]any) {
					root["observatory"] = map[string]any{"subjectSelector": []string{selector.prefix}}
					cfg, _ := root["routing"].(map[string]any)
					if cfg == nil {
						cfg = map[string]any{}
						root["routing"] = cfg
					}
					cfg["balancers"] = []any{map[string]any{"tag": "health", "selector": []string{selector.prefix}}}
				})
			}
			active, err := Prepare(withSelectors(old))
			if err != nil {
				t.Fatal(err)
			}
			next, err := PrepareCached(withSelectors(base), active)
			if err != nil {
				t.Fatal(err)
			}
			blocker := outboundReloadBlocker(active, next)
			if (blocker == "") != selector.allow {
				t.Fatalf("unexpected removal result: %q", blocker)
			}
		})
	}
}
