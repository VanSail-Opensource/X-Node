package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/update"
)

func TestSourceCheckpointFailureKeepsThePublishedEpoch(t *testing.T) {
	for _, published := range []bool{false, true} {
		name := "before_checkpoint"
		if published {
			name = "after_checkpoint"
		}
		t.Run(name, func(t *testing.T) {
			g, _ := guardFixture(t)
			blocked := g.file("bans.json.gz")
			if published {
				blocked = g.file("bans.journal.gz")
			}
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blocked, "obstruction"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			previousEpoch := g.state.JournalEpoch
			now := time.Now().UTC()
			chunk := protocol.FirewallUpdate{Version: 1, SourcesOnly: true, SnapshotID: "new-source", Final: true, SourcesComplete: true, Sources: []protocol.FirewallSource{{ID: "feed", Generation: "first", Until: now.Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"8.8.8.0/24"}}}}
			if err := g.Sync(context.Background(), chunk); err == nil {
				t.Fatal("injected checkpoint failure was not reported")
			}
			if (g.state.JournalEpoch != previousEpoch) != published || (g.state.SourceMasterVersion == 1) != published {
				t.Error("memory disagrees with the durable publication boundary", g.state.SourceMasterVersion, g.state.JournalEpoch, previousEpoch)
			}
			if err := os.RemoveAll(blocked); err != nil {
				t.Fatal(err)
			}
			if err := g.appendJournal(journalRecord{Events: []protocol.FirewallEvent{{Kind: "detected", IP: "8.8.8.8", Rule: "xray_invalid", Count: 1, FirstSeen: now, Time: now}}}); err != nil {
				t.Fatal(err)
			}
			restarted, err := OpenGuard(g.dir, g.manager)
			if err != nil {
				t.Fatal(err)
			}
			if len(restarted.state.Events) != 1 || (restarted.state.SourceMasterVersion == 1) != published {
				t.Fatal("a post-failure journal receipt was lost or an unpublished source became active", restarted.state.SourceMasterVersion, restarted.state.Events)
			}
		})
	}
}

func TestLegacySourceCheckpointWaitsForUpgradeConfirmation(t *testing.T) {
	g, _ := guardFixture(t)
	g.state.Sources["feed"] = sourceState{FirewallSource: protocol.FirewallSource{ID: "feed", Generation: "legacy", Until: time.Now().UTC().Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"8.8.8.0/24"}}}
	if err := g.writeSnapshot(g.state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(g.file("bans.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	updates := filepath.Join(filepath.Dir(g.dir), "updates")
	if err = os.MkdirAll(updates, 0700); err != nil {
		t.Fatal(err)
	}
	tx := update.Transaction{ID: "upgrade", Version: "v2.0.11", Previous: "v2.0.10", Status: "pending", Deadline: time.Now().UTC().Add(time.Minute), NodePath: filepath.Join(updates, "x-node"), CLIPath: filepath.Join(updates, "xnodectl")}
	writeTransaction := func() {
		t.Helper()
		raw, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(updates, "transaction.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeTransaction()
	restarted, err := OpenGuard(g.dir, g.manager)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.legacySources || len(restarted.state.Sources["feed"].Prefixes) != 0 || restarted.state.Sources["feed"].PrefixCount != 1 {
		t.Error("legacy migration lost its format fence or bounded representation")
	}
	if err = restarted.compact(); err == nil {
		t.Error("pending upgrade allowed removal of rollback-readable prefixes")
	}
	after, err := os.ReadFile(g.file("bans.json.gz"))
	if err != nil || !bytes.Equal(before, after) {
		t.Error("pending upgrade changed the legacy checkpoint", err)
	}
	tx.Status = "confirmed"
	writeTransaction()
	if err = restarted.compact(); err != nil {
		t.Fatal(err)
	}
	confirmed, err := OpenGuard(g.dir, g.manager)
	if err != nil || confirmed.legacySources || confirmed.state.Sources["feed"].PrefixCount != 1 {
		t.Fatal("confirmed migration did not retain the source", err)
	}
}
