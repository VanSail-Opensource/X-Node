package firewall

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func publishRangeFile(staged, target string) error {
	if _, err := os.Stat(target); err == nil {
		digest := func(path string) ([32]byte, error) {
			var result [32]byte
			f, e := os.Open(path)
			if e != nil {
				return result, e
			}
			defer f.Close()
			h := sha256.New()
			_, e = io.Copy(h, f)
			copy(result[:], h.Sum(nil))
			return result, e
		}
		a, e := digest(staged)
		if e != nil {
			return e
		}
		b, e := digest(target)
		if e != nil {
			return e
		}
		if a != b {
			return errors.New("source generation contents changed")
		}
		return os.Remove(staged)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staged, target); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
func (g *Guard) cleanupSourceFiles() error {
	g.mu.Lock()
	retain := g.retainBulk
	g.mu.Unlock()
	if retain {
		return nil
	}
	keep := map[string]bool{}
	g.retainCountryFiles(keep)
	g.mu.Lock()
	for id, source := range g.state.Sources {
		if source.Expired {
			continue
		}
		keep[filepath.Base(sourcePath(g.dir, id, source.Generation))] = true
		if source.PreviousGeneration != "" {
			keep[filepath.Base(sourcePath(g.dir, id, source.PreviousGeneration))] = true
		}
	}
	g.mu.Unlock()
	entries, err := os.ReadDir(g.file("bulk"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "src-") && strings.HasSuffix(entry.Name(), ".ranges") && !keep[entry.Name()] {
			if err = os.Remove(filepath.Join(g.file("bulk"), entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
