package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type guardKernel struct {
	*fakeBackend
	mu         sync.Mutex
	bans       []protocol.FirewallBan
	exemptions []protocol.FirewallExemption
	sources    []protocol.FirewallSource
}

func (k *guardKernel) Bans(_ context.Context, bans []protocol.FirewallBan, exemptions []protocol.FirewallExemption, sources []protocol.FirewallSource, replace bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.bans = append([]protocol.FirewallBan(nil), bans...)
	k.exemptions = append([]protocol.FirewallExemption(nil), exemptions...)
	if replace {
		k.sources = protocol.Clone(sources)
	}
	return nil
}
func guardFixture(t *testing.T) (*Guard, *guardKernel) {
	t.Helper()
	manager, _, backend := fixture(t)
	kernel := &guardKernel{fakeBackend: backend}
	manager.Backend = kernel
	pending := applyFixture(t, manager)
	if err := manager.Confirm(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	guard, err := OpenGuard(manager.Dir, manager)
	if err != nil {
		t.Fatal(err)
	}
	configured := policy()
	configured.MasterControlled = true
	guard.Configure(configured)
	return guard, kernel
}
func processHits(t *testing.T, g *Guard, ip, rule string, count int, at time.Time) {
	t.Helper()
	for range count {
		g.hits <- observedHit{ip: netip.MustParseAddr(ip), rule: rule, at: at}
	}
	g.mu.Lock()
	err := g.processHits(at)
	g.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}
func TestDetectionRequiresMasterCommandAndRefreshDoesNotReport(t *testing.T) {
	g, kernel := guardFixture(t)
	now := time.Now().UTC()
	processHits(t, g, "203.0.113.8", "xray_invalid", 2, now)
	if len(g.state.Events) != 0 || len(g.state.Bans) != 0 {
		t.Fatal("threshold caused premature action")
	}
	processHits(t, g, "203.0.113.8", "xray_invalid", 1, now.Add(time.Second))
	events := g.pendingEvents(512)
	if len(events) != 1 || events[0].Count != 3 || len(g.state.Bans) != 0 {
		t.Fatal("detection did not remain report-only", events)
	}
	if len(kernel.bans) != 0 {
		t.Fatal("detector changed kernel blacklist")
	}
	if err := g.appendJournal(journalRecord{Ack: []string{events[0].ID}}); err != nil {
		t.Fatal(err)
	}
	ban := protocol.FirewallBan{Prefix: "203.0.113.8", Generation: "first", Until: now.Add(time.Minute), RefreshSeconds: 300}
	if err := g.Update(context.Background(), protocol.FirewallUpdate{Version: 1, SnapshotID: "first", Bans: []protocol.FirewallBan{ban}}); err != nil {
		t.Fatal(err)
	}
	processHits(t, g, "203.0.113.8", "blacklist", 1, now.Add(2*time.Second))
	if len(g.state.Events) != 0 || !g.state.Bans["203.0.113.8/32"].Until.After(ban.Until) {
		t.Fatal("repeat ban hit reported or did not extend")
	}
	ban.Generation = "shorter"
	ban.Until = now.Add(10 * time.Second)
	ban.RefreshSeconds = 10
	if err := g.Update(context.Background(), protocol.FirewallUpdate{Version: 2, SnapshotID: "second", Bans: []protocol.FirewallBan{ban}}); err != nil {
		t.Fatal(err)
	}
	if !g.state.Bans["203.0.113.8/32"].Until.Equal(ban.Until) {
		t.Fatal("master could not shorten deadline")
	}
	processHits(t, g, "203.0.113.8", "blacklist", 1, now.Add(3*time.Second))
	extended := g.state.Bans["203.0.113.8/32"].Until
	if err := g.Update(context.Background(), protocol.FirewallUpdate{Version: 2, SnapshotID: "second", Bans: []protocol.FirewallBan{ban}}); err != nil {
		t.Fatal(err)
	}
	if !g.state.Bans["203.0.113.8/32"].Until.Equal(extended) {
		t.Fatal("command replay changed local extension")
	}
	g.mu.Lock()
	err := g.expire(now.Add(time.Minute))
	g.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(g.state.Bans) != 0 || len(g.pendingEvents(512)) != 1 {
		t.Fatal("expiry did not emit a durable event")
	}
	processHits(t, g, "203.0.113.8", "xray_invalid", 3, now.Add(2*time.Minute))
	if len(g.pendingEvents(512)) != 2 {
		t.Fatal("short ban expiry suppressed a new threshold window")
	}
}

func TestPendingFirewallEventsUseSharedProtocolBatchLimit(t *testing.T) {
	g := &Guard{state: banState{Events: map[string]protocol.FirewallEvent{}}, eventOrder: []string{}}
	for i := 1; i <= protocol.MaxFirewallEventsPerFrame+1; i++ {
		id := fmt.Sprintf("event-%03d", i)
		g.state.Events[id] = protocol.FirewallEvent{ID: id, Kind: "detected"}
		g.eventOrder = append(g.eventOrder, id)
	}
	first := g.pendingEvents(protocol.MaxFirewallEventsPerFrame)
	if len(first) != protocol.MaxFirewallEventsPerFrame {
		t.Fatalf("first batch size = %d, want %d", len(first), protocol.MaxFirewallEventsPerFrame)
	}
	for _, event := range first {
		delete(g.state.Events, event.ID)
	}
	second := g.pendingEvents(protocol.MaxFirewallEventsPerFrame)
	if len(second) != 1 || second[0].ID != "event-257" {
		t.Fatalf("remaining batch = %#v, want event-257", second)
	}
}

func TestRuleWindowAndPrivateAddresses(t *testing.T) {
	g, _ := guardFixture(t)
	p := policy()
	p.MasterControlled = true
	p.Rules = map[string]protocol.FirewallRule{"xray_invalid": {Enabled: true, Threshold: 2, WindowSeconds: 10}, "xray_tcp_probe": {Enabled: false, Threshold: 3, WindowSeconds: 60}}
	g.Configure(p)
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "fe80::1"} {
		g.Observe(netip.MustParseAddr(ip), "xray_invalid")
	}
	if len(g.hits) != 0 {
		t.Fatal("trusted/private addresses entered detector")
	}
	now := time.Now().UTC()
	processHits(t, g, "203.0.113.8", "xray_invalid", 1, now)
	processHits(t, g, "203.0.113.8", "xray_invalid", 1, now.Add(11*time.Second))
	if len(g.state.Events) != 0 {
		t.Fatal("hits from expired window combined")
	}
	processHits(t, g, "203.0.113.8", "xray_invalid", 1, now.Add(12*time.Second))
	if len(g.state.Events) != 1 {
		t.Fatal("fresh window did not report")
	}
}
