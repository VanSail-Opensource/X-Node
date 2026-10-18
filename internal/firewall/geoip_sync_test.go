package firewall

import (
	"context"
	"net/netip"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestCountryRangesAreStagedOutsideConfiguration(t *testing.T) {
	g, _ := guardFixture(t)
	ctx := context.Background()
	if ready, err := g.SyncGeoIP(ctx, protocol.GeoIPChunk{Generation: "country", Probe: true}); err != nil || ready {
		t.Fatal("missing country ready", err)
	}
	chunk := protocol.GeoIPChunk{Generation: "country", Prefixes: []string{"8.8.8.0/25"}}
	if ready, err := g.SyncGeoIP(ctx, chunk); err != nil || ready {
		t.Fatal("partial country generation published", err)
	}
	chunk.Index = 1
	chunk.Final = true
	chunk.Prefixes = []string{"8.8.8.128/25"}
	if ready, err := g.SyncGeoIP(ctx, chunk); err != nil || !ready {
		t.Fatal("country generation not durable", err)
	}
	if ready, err := g.SyncGeoIP(ctx, protocol.GeoIPChunk{Generation: "country", Probe: true}); err != nil || !ready {
		t.Fatal("country probe changed generation", err)
	}
	if got, err := rangeContains(sourcePath(g.dir, "country", "country"), netip.MustParseAddr("8.8.8.1")); err != nil || !got {
		t.Fatal("country ranges lost", err)
	}
}
