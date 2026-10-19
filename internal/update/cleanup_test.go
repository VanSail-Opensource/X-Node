package update

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConfirmationCleansDownloadsWithoutDeletingRollbackPair(t *testing.T) {
	dir := t.TempDir()
	m := New(filepath.Join(dir, "updates"), "fixture", nil)
	m.NodePath, m.CLIPath = filepath.Join(dir, "agent"), filepath.Join(dir, "cli")
	for _, target := range []string{m.NodePath, m.CLIPath} {
		for _, suffix := range []string{"", ".new", ".old"} {
			if err := os.WriteFile(target+suffix, []byte("private fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := m.Confirm(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{m.NodePath, m.CLIPath} {
		if _, err := os.Stat(target + ".new"); !os.IsNotExist(err) {
			t.Fatal("staged download survived confirmation", err)
		}
		for _, suffix := range []string{"", ".old"} {
			if _, err := os.Stat(target + suffix); err != nil {
				t.Fatal("cleanup removed installed or rollback binary", err)
			}
		}
	}
}
