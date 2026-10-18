package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestDeliveryRetryCannotShortenAnExtendedBan(t *testing.T) {
	g, _ := guardFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ban := protocol.FirewallBan{Prefix: "8.8.8.8", Generation: "one", Until: now.Add(time.Minute), RefreshSeconds: 3600}
	input := protocol.FirewallUpdate{Version: 1, SnapshotID: "attempt-one", Bans: []protocol.FirewallBan{ban}}
	if err := g.Update(ctx, input); err != nil {
		t.Fatal(err)
	}
	processHits(t, g, "8.8.8.8", "closed_port", 1, now.Add(time.Second))
	until := g.state.Bans["8.8.8.8/32"].Until
	input.SnapshotID = "attempt-two"
	if err := g.Update(ctx, input); err != nil {
		t.Fatal(err)
	}
	if !g.state.Bans["8.8.8.8/32"].Until.Equal(until) {
		t.Fatal("same desired version shortened repeat-hit evidence")
	}
}

func TestSourceReferenceCanRefreshItsAuthorizedDeadline(t *testing.T) {
	g, _ := guardFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	source := protocol.FirewallSource{ID: "feed", Generation: "same-content", Until: now.Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"8.8.8.0/24"}}
	if err := g.Sync(ctx, protocol.FirewallUpdate{SourcesOnly: true, Version: 1, SnapshotID: "first", Final: true, Sources: []protocol.FirewallSource{source}}); err != nil {
		t.Fatal(err)
	}
	source.Until = now.Add(2 * time.Hour)
	source.Prefixes = nil
	source.Reference = true
	if err := g.Sync(ctx, protocol.FirewallUpdate{SourcesOnly: true, Version: 2, SnapshotID: "second", Final: true, Sources: []protocol.FirewallSource{source}}); err != nil {
		t.Fatal(err)
	}
	if !g.state.Sources["feed"].Until.Equal(source.Until) || g.Status().SourcePrefixes != 1 {
		t.Fatal("reference lost refreshed deadline or ranges")
	}
}
