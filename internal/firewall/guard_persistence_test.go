package firewall

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestFirstJournalWriteSurvivesRebootAndTornTail(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now().UTC()
	ban := protocol.FirewallBan{Prefix: "203.0.113.9", Generation: "durable", Until: now.Add(time.Hour), RefreshSeconds: 3600}
	if err := g.Update(context.Background(), protocol.FirewallUpdate{Version: 1, SnapshotID: "durable", Bans: []protocol.FirewallBan{ban}}); err != nil {
		t.Fatal(err)
	}
	processHits(t, g, "203.0.113.10", "xray_invalid", 3, now)
	before, err := os.Stat(g.file("bans.journal.gz"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(g.file("bans.journal.gz"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte{0x1f, 0x8b, 0x08}); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenGuard(g.dir, g.manager)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.state.Bans["203.0.113.9/32"].Until.Equal(ban.Until) || len(restarted.pendingEvents(512)) != 1 {
		t.Fatal("reboot lost committed bans/reports")
	}
	if restarted.state.EventNamespace != g.state.EventNamespace || restarted.state.NextEvent != g.state.NextEvent {
		t.Fatal("replay cursor changed across reboot")
	}
	after, err := os.Stat(g.file("bans.journal.gz"))
	if err != nil || before.Size() != after.Size() {
		t.Fatal("torn uncommitted tail was not pruned", err)
	}
}
func TestCompactionAndOldSourceExpiryAckCannotEraseNewGeneration(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now().UTC()
	g.state.Sources["feed"] = sourceState{FirewallSource: protocol.FirewallSource{ID: "feed", Generation: "old", Until: now.Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"8.0.0.0/8"}}}
	if err := g.appendJournal(journalRecord{ExpiredSources: []string{"feed"}, Events: []protocol.FirewallEvent{{Kind: "source_expired", Rule: "feed", Generation: "old", Time: now}}}); err != nil {
		t.Fatal(err)
	}
	event := g.pendingEvents(1)[0]
	oldJournal, err := os.ReadFile(g.file("bans.journal.gz"))
	if err != nil {
		t.Fatal(err)
	}
	newSource := g.state.Sources["feed"]
	newSource.Generation = "new"
	newSource.Expired = false
	g.state.Sources["feed"] = newSource
	if err = g.compact(); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the checkpoint rename but before journal unlink.
	if err = os.WriteFile(g.file("bans.journal.gz"), oldJournal, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenGuard(g.dir, g.manager)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.state.Sources["feed"].Expired {
		t.Fatal("old journal undid checkpoint")
	}
	if err = restarted.appendJournal(journalRecord{Ack: []string{event.ID}}); err != nil {
		t.Fatal(err)
	}
	if restarted.state.Sources["feed"].Generation != "new" {
		t.Fatal("stale source expiry ack erased a newer generation")
	}
}

func TestDuplicateAcknowledgmentsDoNotWriteJournal(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now().UTC()
	if err := g.appendJournal(journalRecord{Events: []protocol.FirewallEvent{{Kind: "detected", IP: "8.8.8.8", Rule: "xray_invalid", Count: 1, FirstSeen: now, Time: now}}}); err != nil {
		t.Fatal(err)
	}
	id := g.pendingEvents(1)[0].ID
	if err := g.acknowledge([]string{id, id}); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(g.file("bans.journal.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if err = g.acknowledge([]string{id, "missing"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(g.file("bans.journal.gz"))
	if err != nil || before.Size() != after.Size() || len(g.state.Events) != 0 {
		t.Fatal("duplicate acknowledgment changed durable journal", err)
	}
	restarted, err := OpenGuard(g.dir, g.manager)
	if err != nil || len(restarted.state.Events) != 0 {
		t.Fatal("acknowledgment did not survive restart", err)
	}
}
