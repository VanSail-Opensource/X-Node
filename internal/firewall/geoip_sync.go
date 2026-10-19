package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// SyncGeoIP keeps bulk country ranges out of desired config and telemetry copies.
func (g *Guard) SyncGeoIP(ctx context.Context, chunk protocol.GeoIPChunk) (bool, error) {
	if !protocol.ValidName(chunk.Generation) || chunk.Index < 0 || chunk.Index > 10000 || len(chunk.Prefixes) > protocol.GeoIPPrefixesPerChunk {
		return false, errors.New("invalid country range chunk")
	}
	path := sourcePath(g.dir, "country", chunk.Generation)
	if chunk.Probe {
		if chunk.Final || len(chunk.Prefixes) > 0 {
			return false, errors.New("country probe cannot mutate")
		}
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			return false, nil
		}
		return err == nil, err
	}
	g.sourceMu.Lock()
	defer g.sourceMu.Unlock()
	release, err := g.lockBulk(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	if g.sourceUpgradePending() {
		return false, errors.New("country synchronization awaits update confirmation")
	}
	if err := os.MkdirAll(g.file("bulk"), 0700); err != nil {
		return false, err
	}
	var staging struct {
		Generation string `json:"generation"`
		Next       int    `json:"next"`
	}
	if raw, err := os.ReadFile(g.file("geoip-sync.json")); err == nil {
		if json.Unmarshal(raw, &staging) != nil {
			return false, errors.New("invalid country staging state")
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if staging.Generation != chunk.Generation {
		if chunk.Index != 0 {
			return false, errors.New("country generation must begin at zero")
		}
		if staging.Generation != "" {
			_ = os.Remove(sourcePath(g.dir, "country", staging.Generation) + ".country")
		}
		staging.Generation, staging.Next = chunk.Generation, 0
		if err := os.Remove(path + ".country"); err != nil && !os.IsNotExist(err) {
			return false, err
		}
	}
	if chunk.Index > staging.Next {
		return false, errors.New("country chunk is out of order")
	}
	if chunk.Index == staging.Next {
		if err := appendSourceRecords(ctx, g.dir, path+".country", chunk.Prefixes); err != nil {
			return false, err
		}
		staging.Next++
		raw, err := json.Marshal(staging)
		if err != nil {
			return false, err
		}
		if err = state.AtomicWrite(g.file("geoip-sync.json"), raw, 0600); err != nil {
			return false, err
		}
	}
	if !chunk.Final {
		return false, nil
	}
	if err := os.Remove(path + ".country-sorted"); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := sortSourceRecords(ctx, g.dir, path+".country", path+".country-sorted"); err != nil {
		return false, err
	}
	if err := publishRangeFile(path+".country-sorted", path); err != nil {
		return false, err
	}
	raw, _ := json.Marshal(map[string]string{"generation": chunk.Generation})
	if err := state.AtomicWrite(g.file("geoip-ready.json"), raw, 0600); err != nil {
		return false, err
	}
	for _, name := range []string{path + ".country", g.file("geoip-sync.json")} {
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			return false, err
		}
	}
	return true, g.cleanupSourceFiles()
}

func (g *Guard) retainCountryFiles(keep map[string]bool) {
	if p := g.policy.Load(); p != nil && p.SourceGeoIP != nil {
		keep[filepath.Base(sourcePath(g.dir, "country", p.SourceGeoIP.Generation))] = true
	}
	for _, name := range []string{"geoip-ready.json", "geoip-previous.json"} {
		var pointer struct {
			Generation string `json:"generation"`
		}
		if raw, err := os.ReadFile(g.file(name)); err == nil && json.Unmarshal(raw, &pointer) == nil && protocol.ValidName(pointer.Generation) {
			keep[filepath.Base(sourcePath(g.dir, "country", pointer.Generation))] = true
		}
	}
	for _, name := range []string{"policy.json", "pending.json", "previous-policy.json"} {
		if record, err := readRecord(g.file(name)); err == nil && record.Policy.SourceGeoIP != nil {
			keep[filepath.Base(sourcePath(g.dir, "country", record.Policy.SourceGeoIP.Generation))] = true
		}
	}
}
