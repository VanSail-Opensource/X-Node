package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSourceFilesMergeAndRecoverWithoutResidentPrefixes(t *testing.T) {
	g, _ := guardFixture(t)
	update := protocol.FirewallUpdate{SourcesOnly: true, Version: 1, SnapshotID: "disk", Final: true, Sources: []protocol.FirewallSource{{ID: "feed", Generation: "first", Until: time.Now().Add(time.Hour), RefreshSeconds: 3600, Prefixes: []string{"8.8.8.128/25", "8.8.8.0/25", "8.8.8.64/26", "2001:4860::/32"}}}}
	if err := g.Sync(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	if source := g.state.Sources["feed"]; len(source.Prefixes) != 0 || source.PrefixCount != 2 {
		t.Fatal("resident or unmerged source", source.PrefixCount)
	}
	for _, test := range []struct {
		ip   string
		want bool
	}{{"8.8.8.1", true}, {"8.8.8.255", true}, {"8.8.9.0", false}, {"2001:4860::1", true}, {"2001:4861::1", false}} {
		got, err := rangeContains(sourcePath(g.dir, "feed", "first"), netip.MustParseAddr(test.ip))
		if err != nil || got != test.want {
			t.Fatalf("%s: %v %v", test.ip, got, err)
		}
	}
	loaded, err := OpenGuard(g.dir, g.manager)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.state.Sources["feed"].Prefixes) != 0 || loaded.Status().SourcePrefixes != 2 {
		t.Fatal("restart reloaded IP list into memory")
	}
}

func TestMillionSourcePrefixesUseBoundedWorkingMemory(t *testing.T) {
	g, _ := guardFixture(t)
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	const total = 1_000_000
	until := time.Now().Add(time.Hour)
	for offset, index := 0, 0; offset < total; offset, index = offset+256, index+1 {
		prefixes := make([]string, 0, 256)
		for i := offset; i < min(offset+256, total); i++ {
			value := uint32(0x08000000) + uint32(i)*16
			prefixes = append(prefixes, fmt.Sprintf("%d.%d.%d.%d/32", value>>24, byte(value>>16), byte(value>>8), byte(value)))
		}
		chunk := protocol.FirewallUpdate{SourcesOnly: true, Version: 1, SnapshotID: "million", Index: index, Final: offset+256 >= total, Sources: []protocol.FirewallSource{{ID: "large", Generation: "million", Until: until, RefreshSeconds: 3600, Prefixes: prefixes}}}
		if err := g.Sync(context.Background(), chunk); err != nil {
			t.Fatal(err)
		}
		if index%64 == 0 {
			runtime.GC()
			var current runtime.MemStats
			runtime.ReadMemStats(&current)
			if current.HeapInuse > baseline.HeapInuse+(64<<20) {
				t.Fatalf("source heap grew %d", current.HeapInuse-baseline.HeapInuse)
			}
		}
	}
	if g.state.Sources["large"].PrefixCount != total || len(g.state.Sources["large"].Prefixes) != 0 {
		t.Fatal("large feed was lost or retained")
	}
	if err := bulkAdmission(g.dir, bulkDiskLimit); err == nil {
		t.Fatal("disk admission ignored existing data")
	}
	if _, err := os.Stat(sourcePath(g.dir, "large", "million")); err != nil {
		t.Fatal(err)
	}
}
