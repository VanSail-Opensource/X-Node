package firewall

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
)

type stagedBans struct {
	SourcesOnly bool   `json:"sources_only"`
	Version     uint64 `json:"version"`
	ID          string `json:"id"`
	Next        int    `json:"next"`
}

// Sync stages ordered gzip members and publishes a complete snapshot only when
// its final chunk is durable. The fixed staging paths cannot accumulate files.
func (g *Guard) Sync(ctx context.Context, update protocol.FirewallUpdate) error {
	if err := validateUpdate(update); err != nil {
		return err
	}
	if !protocol.ValidName(update.SnapshotID) || update.Index < 0 || update.Index > 10000 {
		return errors.New("invalid firewall snapshot")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	currentVersion := g.state.MasterVersion
	if update.SourcesOnly {
		currentVersion = g.state.SourceMasterVersion
	}
	if update.Version < currentVersion {
		return nil
	}
	if !update.SourcesOnly && update.Version == g.state.MasterVersion && update.SnapshotID == g.state.SnapshotID {
		if g.dirty {
			return g.enforce(ctx)
		}
		return nil
	}
	if err := g.flushPending(); err != nil {
		return err
	}
	if policy := g.policy.Load(); policy == nil || !policy.Enabled {
		return errors.New("firewall policy is not active")
	}
	if err := state.AtomicWrite(g.file("controlled-v1"), []byte("v1\n"), 0600); err != nil {
		return err
	}

	var staging stagedBans
	if raw, err := os.ReadFile(g.file("sync.json")); err == nil {
		if json.Unmarshal(raw, &staging) != nil {
			return errors.New("invalid firewall staging metadata")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if staging.ID != update.SnapshotID {
		if update.Index != 0 {
			return errors.New("firewall snapshot must start at zero")
		}
		if err := os.MkdirAll(g.dir, 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(g.file("sync.json.gz"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err = file.Close(); err != nil {
			return err
		}
		staging = stagedBans{ID: update.SnapshotID, Version: update.Version, SourcesOnly: update.SourcesOnly}
	}
	if staging.Version != update.Version || staging.SourcesOnly != update.SourcesOnly {
		return errors.New("firewall snapshot version differs")
	}
	if update.Index > staging.Next {
		return errors.New("firewall snapshot chunk is out of order")
	}
	if update.Index == staging.Next {
		file, err := os.OpenFile(g.file("sync.json.gz"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		writer := gzip.NewWriter(file)
		writeErr := json.NewEncoder(writer).Encode(update)
		gzipErr := writer.Close()
		syncErr := file.Sync()
		closeErr := file.Close()
		if err = errors.Join(writeErr, gzipErr, syncErr, closeErr); err != nil {
			return err
		}
		staging.Next++
		raw, err := json.Marshal(staging)
		if err != nil {
			return err
		}
		if err = state.AtomicWrite(g.file("sync.json"), raw, 0600); err != nil {
			return err
		}
	}
	if !update.Final {
		return nil
	}
	if err := g.commitSnapshot(update.SnapshotID, update.Version, update.SourcesOnly); err != nil {
		return err
	}
	return g.enforceMode(ctx, update.SourcesOnly)
}
