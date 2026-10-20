package firewall

import (
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
	"time"
)

func TestLegacySourceBanOverflowIsTrimmedDurablyOnStartup(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now()
	master := protocol.FirewallBan{Prefix: "1.1.1.1/32", Generation: "master", Until: now.Add(time.Minute), RefreshSeconds: 3600}
	g.state.Bans[master.Prefix] = master
	for i := 0; i < sourceBanLimit+1; i++ {
		prefix := fmt.Sprintf("8.%d.%d.%d/32", i>>16, byte(i>>8), byte(i))
		g.state.Bans[prefix] = protocol.FirewallBan{Prefix: prefix, Generation: "feed", Source: "feed", Until: now.Add(time.Duration(i+1) * time.Second), RefreshSeconds: 3600}
	}
	if err := g.compact(); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenGuard(g.dir, g.manager)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.sourceBanCount != sourceBanLimit || loaded.dropped.Load() != 1 || loaded.state.Bans[master.Prefix].Generation != "master" {
		t.Fatal("startup capacity policy lost", loaded.sourceBanCount)
	}
	if _, ok := loaded.state.Bans["8.0.0.0/32"]; ok {
		t.Fatal("soonest-expiring source ban retained")
	}
	reopened, err := OpenGuard(g.dir, g.manager)
	if err != nil || len(reopened.state.Bans) != sourceBanLimit+1 || reopened.dropped.Load() != 0 {
		t.Fatal("trim was not durable", err)
	}
}

func TestStoredMasterCapacityUsesLaterDeadlineWithoutDroppingSourceFacts(t *testing.T) {
	now := time.Now()
	bans := map[string]protocol.FirewallBan{
		"soon": {Prefix: "soon", Until: now}, "later": {Prefix: "later", Until: now.Add(time.Hour)}, "feed": {Prefix: "feed", Source: "feed", Until: now},
	}
	if dropped := trimStoredBans(bans, false, 1); dropped != 1 || bans["later"].Prefix == "" || bans["feed"].Prefix == "" {
		t.Fatal(bans, dropped)
	}
}
