package firewall

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestExpiryWaitsForReportCapacityWithoutExtendingRestrictions(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now().UTC()
	for i := range 4096 {
		id := fmt.Sprintf("queued-%d", i)
		g.state.Events[id] = protocol.FirewallEvent{ID: id, Kind: "detected", IP: "8.8.8.8", Rule: "xray_invalid", Count: 1, Time: now, FirstSeen: now}
		g.eventOrder = append(g.eventOrder, id)
	}
	ban := protocol.FirewallBan{Prefix: "8.8.8.8/32", Generation: "expired", Until: now.Add(-time.Second), RefreshSeconds: 60}
	g.state.Bans[ban.Prefix] = ban
	g.state.Sources["feed"] = sourceState{FirewallSource: protocol.FirewallSource{ID: "feed", Generation: "expired", Until: ban.Until, RefreshSeconds: 60}}
	if err := g.expire(now); err != nil {
		t.Fatal(err)
	}
	if len(g.state.Events) > 4096 || len(g.state.Bans) != 1 || g.state.Sources["feed"].Expired || !g.state.Sources["feed"].BaseExpired {
		t.Error("expiry exceeded report capacity or lost deferred retirement")
	}
	if status := g.Status(); status.ActiveBans != 0 || status.Sources != 0 {
		t.Fatal("backpressure extended an expired restriction", status)
	}
	for _, id := range []string{"queued-0", "queued-1"} {
		if err := g.acknowledge([]string{id}); err != nil {
			t.Fatal(err)
		}
		if err := g.expire(now); err != nil {
			t.Fatal(err)
		}
		if len(g.state.Events) > 4096 {
			t.Fatal("deferred expiry exceeded its freed report capacity")
		}
	}
	if len(g.state.Bans) != 0 || !g.state.Sources["feed"].Expired {
		t.Fatal("acknowledgments did not resume deferred retirement")
	}
}

func TestImmediateExemptionsRespectSnapshotCapacity(t *testing.T) {
	g, _ := guardFixture(t)
	until := time.Now().UTC().Add(time.Hour)
	for i := range 100000 {
		ip := fmt.Sprintf("8.%d.%d.%d", i>>16, byte(i>>8), byte(i))
		g.state.Exemptions[ip] = protocol.FirewallExemption{IP: ip, Generation: "existing", Until: until}
	}
	grant := protocol.FirewallExemption{IP: "9.9.9.9", Generation: "new", Until: until}
	input := protocol.FirewallUpdate{Version: 1, SnapshotID: "new-grant", Exemptions: []protocol.FirewallExemption{grant}}
	if err := g.Update(context.Background(), input); err == nil {
		t.Error("immediate update bypassed the full snapshot exemption limit")
	}
	if len(g.state.Exemptions) != 100000 || g.state.MasterVersion != 0 {
		t.Fatal("rejected grant changed the durable desired state")
	}
	input.RemoveExemptions = []string{"8.0.0.0", "8.0.0.0"}
	if err := g.Update(context.Background(), input); err != nil {
		t.Fatal("replacement within capacity was rejected", err)
	}
	if len(g.state.Exemptions) != 100000 || g.state.Exemptions[grant.IP].Generation != grant.Generation {
		t.Fatal("replacement was not applied")
	}
}
