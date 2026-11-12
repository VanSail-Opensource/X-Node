package geodata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recoveryGeneration(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, strings.Repeat(name, 64))
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "geosite.dat"), []byte("retained generation"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUncertainGenerationPointersCannotAuthorizeCleanup(t *testing.T) {
	for _, operation := range []string{"prepare cleanup", "activation"} {
		for _, name := range []string{"active.json", "previous.json"} {
			for _, malformed := range []string{"null", "{}", `{"generation":"invalid"}`, `{"generation":"` + strings.Repeat("a", 64) + `","generation":"` + strings.Repeat("b", 64) + `"}`, "truncated"} {
				t.Run(operation+"/"+name+"/"+malformed, func(t *testing.T) {
					dir := t.TempDir()
					retained := recoveryGeneration(t, dir, "a")
					candidate := recoveryGeneration(t, dir, "b")
					if err := os.WriteFile(filepath.Join(dir, "active.json"), []byte(`{"generation":"`+filepath.Base(candidate)+`"}`), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, name), []byte(malformed), 0600); err != nil {
						t.Fatal(err)
					}
					var err error
					if operation == "activation" {
						err = Activate(dir, candidate)
					} else {
						err = prunePrepared(dir, candidate)
					}
					if err == nil {
						t.Error("uncertain generation pointer authorized publication/cleanup")
					}
					if raw, err := os.ReadFile(filepath.Join(retained, "geosite.dat")); err != nil || string(raw) != "retained generation" {
						t.Fatal("possible serving/rollback assets were deleted", err)
					}
					if raw, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(raw) != malformed {
						t.Fatal("uncertain recovery evidence was overwritten", err)
					}
				})
			}
		}
	}
}

func TestGenerationPointersRetainLegacyFlatDirectory(t *testing.T) {
	dir := t.TempDir()
	flat := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(flat, []byte("legacy assets"), 0600); err != nil {
		t.Fatal(err)
	}
	candidate := recoveryGeneration(t, dir, "b")
	for i := 0; i < 2; i++ {
		if err := Activate(dir, candidate); err != nil {
			t.Fatal("legacy first/repeated activation failed", err)
		}
	}
	if Resolve(dir) != candidate {
		t.Fatal("generation did not activate")
	}
	if raw, err := os.ReadFile(flat); err != nil || string(raw) != "legacy assets" {
		t.Fatal("legacy flat asset changed", err)
	}
}
