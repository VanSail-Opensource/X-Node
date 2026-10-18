package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestCIDRExemptionsMatchOnlyTheirRangeAndLifetime(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now().UTC()
	update := protocol.FirewallUpdate{Version: 1, SnapshotID: "cidr", Exemptions: []protocol.FirewallExemption{{IP: "8.8.8.9/24", Generation: "grant", Until: now.Add(time.Hour)}}}
	if err := g.Update(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	if !g.exempt(netip.MustParseAddr("8.8.8.100"), now) || g.exempt(netip.MustParseAddr("8.8.9.1"), now) || g.exempt(netip.MustParseAddr("8.8.8.100"), now.Add(2*time.Hour)) {
		t.Fatal("CIDR exemption scope or deadline changed")
	}
	if _, exists := g.state.Exemptions["8.8.8.0/24"]; !exists {
		t.Fatal("grant was not canonical")
	}
}
