package xray

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
)

func TestServingDNSAndSessionPolicySwapThroughStableFeatures(t *testing.T) {
	config := protocol.Config{Xray: json.RawMessage(`{"inbounds":[],"log":{"loglevel":"none"}}`)}
	r := New(sessions.New())
	defer r.Stop()
	if err := r.Apply(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	original := r.instance
	resolver := original.GetFeature(dns.ClientType()).(*reloadableDNS)
	manager := original.GetFeature(policy.ManagerType()).(policy.Manager)
	if !resolver.MayUseSystemResolver() {
		t.Fatal("missing DNS section did not retain the local resolver")
	}
	next := editNative(t, config, func(root map[string]any) {
		root["dns"] = map[string]any{"hosts": map[string]any{"reload.test": "192.0.2.11"}}
		root["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"connIdle": 47}}}
	})
	if err := r.Apply(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	assertResolverIP := func(want string) {
		t.Helper()
		ips, _, err := resolver.LookupIP("reload.test", dns.IPOption{IPv4Enable: true})
		if err != nil || len(ips) != 1 || ips[0].String() != want {
			t.Fatalf("DNS resolved to %v (%v), want %s", ips, err, want)
		}
	}
	assertResolverIP("192.0.2.11")
	if got := manager.ForLevel(0).Timeouts.ConnectionIdle; got != 47*time.Second {
		t.Fatalf("policy timeout not published: %s", got)
	}
	invalidDNS := editNative(t, next, func(root map[string]any) {
		root["dns"].(map[string]any)["script"] = "function NotAHandler() end"
		root["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"connIdle": 71}}}
	})
	if err := r.Apply(context.Background(), invalidDNS); err == nil {
		t.Fatal("candidate DNS script without a query handler started")
	}
	assertResolverIP("192.0.2.11")
	if got := manager.ForLevel(0).Timeouts.ConnectionIdle; got != 47*time.Second {
		t.Fatalf("failed DNS candidate published a new policy: %s", got)
	}
	if err := r.Apply(context.Background(), config); err != nil || r.instance != original {
		t.Fatal("removing DNS policy changed the serving instance", err)
	}
	if _, explicit := resolver.active.client.(interface{ IsOwnLink(context.Context) bool }); explicit {
		t.Fatal("removing the DNS section did not restore the system resolver")
	}

	systemChange := editNative(t, next, func(root map[string]any) {
		root["dns"] = map[string]any{"hosts": map[string]any{"reload.test": "192.0.2.12"}}
		root["policy"].(map[string]any)["system"] = map[string]any{"statsInboundUplink": true}
	})
	if err := r.Apply(context.Background(), systemChange); err != nil {
		t.Fatalf("valid cold-only system policy failed activation: %v", err)
	}
	if r.instance == original || !r.Ready() || r.Statistics().LastMode != "cold_reload" {
		t.Fatal("a changed system counter policy should rebuild the embedded core")
	}
	if !r.instance.GetFeature(policy.ManagerType()).(policy.Manager).ForSystem().Stats.InboundUplink {
		t.Fatal("the new runtime did not publish the requested system policy")
	}
	resolver = r.instance.GetFeature(dns.ClientType()).(*reloadableDNS)
	assertResolverIP("192.0.2.12")
}

type heldResolver struct {
	dns.Client
	tag             string
	entered, resume chan struct{}
	closed, called  atomic.Bool
}

func (s *heldResolver) LookupIP(_ string, _ dns.IPOption) ([]xnet.IP, uint32, error) {
	s.called.Store(true)
	if s.entered != nil {
		close(s.entered)
		<-s.resume
	}
	return nil, 0, nil
}
func (s *heldResolver) IsOwnLink(ctx context.Context) bool {
	in := session.InboundFromContext(ctx)
	return in != nil && in.Tag == s.tag
}
func (s *heldResolver) Close() error {
	s.closed.Store(true)
	return nil
}

func TestDNSSwapKeepsInFlightLookupAndItsLoopGuard(t *testing.T) {
	old := &heldResolver{tag: "old-dns", entered: make(chan struct{}), resume: make(chan struct{})}
	next := &heldResolver{tag: "new-dns"}
	wrapper := &reloadableDNS{active: &dnsGeneration{client: old, cancel: func() {}}}
	defer wrapper.Close()
	result := make(chan error, 1)
	go func() {
		_, _, err := wrapper.LookupIP("reload.test", dns.IPOption{IPv4Enable: true})
		result <- err
	}()
	select {
	case <-old.entered:
	case <-time.After(time.Second):
		t.Fatal("lookup did not reach resolver")
	}
	defer func() {
		select {
		case <-old.resume:
		default:
			close(old.resume)
		}
	}()
	if closeNow := wrapper.replace(&dnsGeneration{client: next, cancel: func() {}}); closeNow != nil {
		t.Fatal("in-flight resolver was eligible for closing")
	}
	oldContext := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: old.tag})
	newContext := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: next.tag})
	if old.closed.Load() || !wrapper.IsOwnLink(oldContext) || !wrapper.IsOwnLink(newContext) {
		t.Fatal("DNS generation lost an in-flight lookup or its loop guard")
	}
	if _, _, err := wrapper.LookupIP("reload.test", dns.IPOption{IPv4Enable: true}); err != nil || !next.called.Load() {
		t.Fatal("new lookup did not reach replacement resolver", err)
	}
	close(old.resume)
	if err := <-result; err != nil || !old.closed.Load() || wrapper.IsOwnLink(oldContext) {
		t.Fatal("finished lookup did not retire the old resolver", err)
	}
}
