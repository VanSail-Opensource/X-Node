package xray

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

type testOutboundHandler struct {
	outbound.Handler
	tag      string
	closed   atomic.Int32
	dispatch func()
}

func (h *testOutboundHandler) Tag() string                               { return h.tag }
func (*testOutboundHandler) Start() error                                { return nil }
func (h *testOutboundHandler) Close() error                              { h.closed.Add(1); return nil }
func (h *testOutboundHandler) Dispatch(context.Context, *transport.Link) { h.dispatch() }

func TestOutboundPublicationPinsPreselectedHandlerThroughDispatch(t *testing.T) {
	m := &managedManager{bridge: &integration{}, retired: make(map[*outboundLifetime]struct{})}
	m.store(&outboundTable{tagged: make(map[string]*managedOutbound)})
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	old := &testOutboundHandler{tag: "direct", dispatch: func() { close(started); <-finish }}
	if err := m.AddHandler(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	selected := m.GetHandler("direct")
	replacement := m.newHandler(&testOutboundHandler{tag: "direct"})
	original := m.table.Load()
	stage := &outboundUpdate{
		manager: m, original: original, primaryTag: "direct", stats: &Statistics{},
		previous: map[string]*managedOutbound{"direct": original.tagged["direct"]},
		created:  map[string]*managedOutbound{"direct": replacement},
	}
	if err := stage.publish(); err != nil {
		t.Fatal(err)
	}
	stage.commit()
	stage.abort() // Deferred after a successful Runtime.applyLive.
	if m.GetHandler("direct") != replacement || m.GetDefaultHandler() != replacement {
		t.Fatal("the replacement was not installed for new selections")
	}
	runtime.GC()
	if old.closed.Load() != 0 {
		t.Fatal("preselected handler was closed before dispatch")
	}
	go func(h outbound.Handler) { h.Dispatch(context.Background(), nil); close(done) }(selected)
	<-started
	runtime.GC()
	if old.closed.Load() != 0 {
		close(finish)
		<-done
		t.Fatal("retired handler was closed during dispatch")
	}
	close(finish)
	<-done
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if old.closed.Load() != 1 {
		t.Fatal("retired handler was not closed on shutdown")
	}
}

func TestOutboundRemovalCannotRaceEarlierRoutingDecision(t *testing.T) {
	config, _ := testConfig(t)
	config = editNative(t, config, func(root map[string]any) {
		root["outbounds"] = append(root["outbounds"].([]any), map[string]any{"tag": "alternate", "protocol": "freedom"})
		root["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "port": "443", "outboundTag": "alternate"}}}
	})
	withRule, err := Prepare(config)
	if err != nil {
		t.Fatal(err)
	}
	config = editNative(t, config, func(root map[string]any) { delete(root, "routing") })
	withoutRule, err := PrepareCached(config, withRule)
	if err != nil {
		t.Fatal(err)
	}
	config = editNative(t, config, func(root map[string]any) { root["outbounds"] = root["outbounds"].([]any)[:1] })
	withoutOutbound, err := PrepareCached(config, withoutRule)
	if err != nil {
		t.Fatal(err)
	}
	var manager managedManager
	if err := manager.checkRouteHistory(withRule, withoutRule); err != nil {
		t.Fatal(err)
	}
	if err := manager.checkRouteHistory(withoutRule, withoutOutbound); !errors.Is(err, ErrReloadUnsupported) {
		t.Fatal("historically routed outbound removal was not rejected", err)
	}
}
