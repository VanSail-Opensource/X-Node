package firewall

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAbandonedStageCleanupInvalidatesCursorButRetainsCommittedRanges(t *testing.T) {
	g, _ := guardFixture(t)
	ctx := context.Background()
	update := protocol.FirewallUpdate{Version: 1, SnapshotID: "abandoned", SourcesOnly: true, Sources: []protocol.FirewallSource{{ID: "feed", Generation: "one", Until: time.Now().Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"8.8.8.0/24"}}}}
	if err := g.Sync(ctx, update); err != nil {
		t.Fatal(err)
	}
	staged := sourcePath(g.dir, "feed", "one") + ".staging"
	committed := sourcePath(g.dir, "preserved", "active")
	if err := os.WriteFile(committed, []byte("rollback fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-25 * time.Hour)
	for _, path := range []string{staged, committed} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.pruneAbandonedStages(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatal("recent transfer cursor did not protect its older chunks", err)
	}
	if err := os.Chtimes(g.file("source-sync.json"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := g.pruneAbandonedStages(ctx, now); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{staged, g.file("source-sync.json")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("abandoned stage or cursor survived", err)
		}
	}
	if _, err := os.Stat(committed); err != nil {
		t.Fatal("stage cleanup removed committed ranges", err)
	}
	update.Index, update.Final = 1, true
	if err := g.Sync(ctx, update); err == nil {
		t.Fatal("stale cursor published an incomplete replacement")
	}
}
