package geodata

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAbandonedAssetCleanupKeepsGenerationsAndRecentDownloads(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	for _, name := range []string{".assets-abandoned", ".assets-live", strings.Repeat("a", 64)} {
		path := filepath.Join(dir, name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if name != ".assets-live" {
			old := now.Add(-25 * time.Hour)
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := pruneAbandonedStages(context.Background(), dir, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".assets-abandoned")); !os.IsNotExist(err) {
		t.Fatal("orphan asset stage survived", err)
	}
	for _, name := range []string{".assets-live", strings.Repeat("a", 64)} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal("serving/rollback generation or live download removed", err)
		}
	}
}
