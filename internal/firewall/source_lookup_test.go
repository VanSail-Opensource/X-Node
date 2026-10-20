package firewall

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSourceLookupResidentAndSparseWithoutReopen(t *testing.T) {
	for _, resident := range []bool{false, true} {
		t.Run(map[bool]string{true: "resident", false: "sparse"}[resident], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ranges")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 1025 {
				ip := netip.AddrFrom4([4]byte{8, byte(i >> 8), byte(i), 0})
				r, err := prefixRecord(ip.String() + "/32")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.Write(r[:]); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			budget, sparse := int64(0), int64(4<<20)
			if resident {
				budget = sourceLookupBytes
			}
			var lookup sourceLookup
			if err = lookup.open(path, &budget, &sparse); err != nil {
				t.Fatal(err)
			}
			if lookup.file != nil {
				defer lookup.file.Close()
			}
			// Removing the pathname is portable only after the resident read; the
			// cached handle itself proves subsequent sparse reads need no reopen.
			if resident {
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			for _, raw := range []string{"8.0.0.0", "8.1.0.0", "8.4.0.0"} {
				if got, err := lookup.contains(netip.MustParseAddr(raw)); err != nil || !got {
					t.Fatal(raw, got, err)
				}
			}
			if got, err := lookup.contains(netip.MustParseAddr("8.1.0.1")); got || err != nil {
				t.Fatal(got, err)
			}
		})
	}
}

func TestSourceLookupRevisionReplacesCachedError(t *testing.T) {
	g, _ := guardFixture(t)
	until := time.Now().Add(time.Hour)
	g.state.Sources["feed"] = sourceState{FirewallSource: protocol.FirewallSource{ID: "feed", Generation: "first", Until: until}}
	_, _ = g.sourceBan(netip.MustParseAddr("8.8.8.8"), time.Now())
	if len(g.lookups) != 1 || g.lookups[0].err == nil {
		t.Fatal("missing error cache")
	}
	if err := os.MkdirAll(g.file("bulk"), 0700); err != nil {
		t.Fatal(err)
	}
	r, _ := prefixRecord("8.8.8.0/24")
	if err := os.WriteFile(sourcePath(g.dir, "feed", "second"), r[:], 0600); err != nil {
		t.Fatal(err)
	}
	s := g.state.Sources["feed"]
	s.Generation = "second"
	g.state.Sources["feed"] = s
	g.state.SourceRevision++
	ban, ok := g.sourceBan(netip.MustParseAddr("8.8.8.8"), time.Now())
	if !ok || ban.Generation != "second" {
		t.Fatal("revision retained stale lookup")
	}
}
