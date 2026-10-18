package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func (g *Guard) lockBulk(ctx context.Context) (func(), error) {
	if err := os.MkdirAll(g.dir, 0700); err != nil {
		return nil, err
	}
	release, err := lockContext(ctx, g.file("bulk.lock"))
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(release) }, nil
}

// Called only under the cross-process bulk lock. Raw staging files remain
// resumable; sort/migration temporaries can always be reconstructed from them.
func (g *Guard) cleanupBulkScratch() error {
	entries, err := os.ReadDir(g.file("bulk"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && (strings.HasPrefix(name, "sort-") || strings.HasPrefix(name, "migration-") || strings.HasSuffix(name, ".sorted") || strings.HasSuffix(name, ".country-sorted")) {
			if err := os.Remove(filepath.Join(g.file("bulk"), name)); err != nil {
				return err
			}
		}
	}
	return nil
}
