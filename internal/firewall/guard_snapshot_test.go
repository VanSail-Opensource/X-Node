package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSnapshotStagingReferencesAndStaleVersions(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now().UTC()
	namespace := g.state.EventNamespace
	source := protocol.FirewallSource{ID: "feed", Generation: "feed-one", Until: now.Add(time.Minute), RefreshSeconds: 300, Prefixes: []string{"8.0.0.0/8"}}
	chunk := protocol.FirewallUpdate{Version: 1, SourcesOnly: true, SnapshotID: "snapshot-one", Sources: []protocol.FirewallSource{source}}
	if err := g.Sync(context.Background(), chunk); err != nil {
		t.Fatal(err)
	}
	if len(g.state.Sources) != 0 {
		t.Fatal("partial snapshot changed active sources")
	}
	chunk.Index = 1
	chunk.Final = true
	chunk.SourcesComplete = true
	chunk.Sources[0].Prefixes = []string{"2001:4860::/32"}
	if err := g.Sync(context.Background(), chunk); err != nil {
		t.Fatal(err)
	}
	if g.state.Sources["feed"].PrefixCount != 2 || len(g.state.Sources["feed"].Prefixes) != 0 {
		t.Fatal("CIDRs were expanded or omitted")
	}
	processHits(t, g, "8.8.8.8", "source_match", 1, now.Add(time.Second))
	if len(g.state.Events) != 1 || len(g.state.Bans) != 0 {
		t.Fatal("source match did not remain report-only")
	}
	source.Reference = true
	source.Prefixes = nil
	if err := g.Sync(context.Background(), protocol.FirewallUpdate{Version: 2, SourcesOnly: true, SnapshotID: "snapshot-two", Final: true, SourcesComplete: true, Sources: []protocol.FirewallSource{source}}); err != nil {
		t.Fatal(err)
	}
	if g.state.Sources["feed"].PrefixCount != 2 || len(g.state.Sources["feed"].Prefixes) != 0 || len(g.state.Bans) != 0 || g.state.EventNamespace != namespace {
		t.Fatal("source reference discarded state")
	}
	if err := g.Sync(context.Background(), protocol.FirewallUpdate{Version: 1, SourcesOnly: true, SnapshotID: "snapshot-one", Final: true, SourcesComplete: true}); err != nil {
		t.Fatal(err)
	}
	if len(g.state.Sources) != 1 || g.state.SourceMasterVersion != 2 {
		t.Fatal("stale snapshot replaced newer desired state")
	}
}
func TestIPv6ExactExemptionDoesNotRemoveSubnetBan(t *testing.T) {
	g, kernel := guardFixture(t)
	now := time.Now().UTC()
	ban := protocol.FirewallBan{Prefix: "2001:4860:1234:5678::/64", Generation: "subnet", Until: now.Add(time.Hour), RefreshSeconds: 3600}
	exemption := protocol.FirewallExemption{IP: "2001:4860:1234:5678::8", Generation: "paid", Until: now.Add(time.Hour)}
	if err := g.Update(context.Background(), protocol.FirewallUpdate{Version: 1, SnapshotID: "paid", Bans: []protocol.FirewallBan{ban}, Exemptions: []protocol.FirewallExemption{exemption}}); err != nil {
		t.Fatal(err)
	}
	processHits(t, g, exemption.IP, "xray_invalid", 3, now)
	if len(g.state.Events) != 0 || len(kernel.bans) != 1 || len(kernel.exemptions) != 1 {
		t.Fatal("paid exemption removed shared ban or allowed reporting")
	}
}

func TestSourceSnapshotPreservesNewerExactExemption(t *testing.T) {
	g, _ := guardFixture(t)
	ctx := context.Background()
	until := time.Now().UTC().Add(time.Hour)
	chunk := protocol.FirewallUpdate{Version: 1, SourcesOnly: true, SnapshotID: "source-one", Sources: []protocol.FirewallSource{{ID: "feed", Generation: "feed-one", Until: until, RefreshSeconds: 3600, Prefixes: []string{"2001:4860::/32"}}}}
	if err := g.Sync(ctx, chunk); err != nil {
		t.Fatal(err)
	}
	exemption := protocol.FirewallExemption{IP: "2001:4860::8", Generation: "paid", Until: until}
	if err := g.Update(ctx, protocol.FirewallUpdate{Version: 2, SnapshotID: "paid", Exemptions: []protocol.FirewallExemption{exemption}}); err != nil {
		t.Fatal(err)
	}
	chunk.Index, chunk.Final, chunk.SourcesComplete, chunk.Sources = 1, true, true, nil
	if err := g.Sync(ctx, chunk); err != nil {
		t.Fatal(err)
	}
	if len(g.state.Exemptions) != 1 || g.state.MasterVersion != 2 || g.state.SourceMasterVersion != 1 {
		t.Fatal("source publication rolled back dynamic exemption")
	}
}
