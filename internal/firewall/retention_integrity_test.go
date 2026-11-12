package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountryCleanupRetainsRangesWhenRecoveryMetadataIsUncertain(t *testing.T) {
	for _, name := range []string{"geoip-ready.json", "geoip-previous.json", "policy.json", "pending.json", "previous-policy.json"} {
		for _, malformed := range []string{"null", "{}", "truncated"} {
			t.Run(name+"/"+malformed, func(t *testing.T) {
				g := &Guard{dir: t.TempDir(), state: emptyBans()}
				if err := os.Mkdir(g.file("bulk"), 0700); err != nil {
					t.Fatal(err)
				}
				path := sourcePath(g.dir, "country", "retained")
				if err := os.WriteFile(path, []byte("recovery evidence"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(g.file(name), []byte(malformed), 0600); err != nil {
					t.Fatal(err)
				}
				if err := g.cleanupSourceFiles(); err == nil {
					t.Error("uncertain recovery metadata authorized range cleanup")
				}
				if raw, err := os.ReadFile(path); err != nil || string(raw) != "recovery evidence" {
					t.Fatal("cleanup destroyed possible recovery dependencies", err)
				}
			})
		}
	}
}

func TestCountryCleanupStillRetiresKnownUnreferencedRanges(t *testing.T) {
	g := &Guard{dir: t.TempDir(), state: emptyBans()}
	if err := os.Mkdir(g.file("bulk"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, generation := range []string{"kept", "retired"} {
		if err := os.WriteFile(sourcePath(g.dir, "country", generation), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := g.file("bulk/operator-notes.txt")
	external := filepath.Join(t.TempDir(), "caller-owned.ranges")
	for _, path := range []string{unrelated, external} {
		if err := os.WriteFile(path, []byte("caller-owned evidence"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(external, g.file("bulk/src-obsolete-link.ranges")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(g.file("geoip-ready.json"), []byte(`{"generation":"kept"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := g.cleanupSourceFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sourcePath(g.dir, "country", "kept")); err != nil {
		t.Fatal("referenced ranges lost", err)
	}
	if _, err := os.Stat(sourcePath(g.dir, "country", "retired")); !os.IsNotExist(err) {
		t.Fatal("unreferenced ranges were not retired", err)
	}
	for _, path := range []string{unrelated, external} {
		if raw, err := os.ReadFile(path); err != nil || string(raw) != "caller-owned evidence" {
			t.Fatal("range cleanup changed an unrelated file or followed a symlink", path, err)
		}
	}
}
