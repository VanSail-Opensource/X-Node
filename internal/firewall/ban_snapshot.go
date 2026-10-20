package firewall

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"io"
	"os"
	"time"
)

// Dynamic snapshots never share staging or reconstruction with source feeds.
func (g *Guard) commitSnapshot(id string, version uint64) error {
	file, err := os.Open(g.file("sync.json.gz"))
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()
	next := emptyBans()
	next.MasterVersion = version
	next.SourceMasterVersion = g.state.SourceMasterVersion
	next.SourceRevision = g.state.SourceRevision
	next.Revision = g.state.Revision + 1
	next.EventNamespace = g.state.EventNamespace
	next.NextEvent = g.state.NextEvent
	next.SnapshotID = id
	next.Events = g.state.Events
	next.Sources = g.state.Sources
	seen := map[int]bool{}
	decoder := json.NewDecoder(io.LimitReader(reader, maxBanStateBytes+1))
	for {
		var chunk protocol.FirewallUpdate
		if err = decoder.Decode(&chunk); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if chunk.SnapshotID != id || chunk.Version != version || chunk.SourcesOnly {
			return errors.New("dynamic snapshot identity differs")
		}
		if seen[chunk.Index] {
			continue
		}
		seen[chunk.Index] = true
		for _, ban := range chunk.Bans {
			prefix, _ := protocol.FirewallPrefix(ban.Prefix)
			ban.Prefix = prefix.String()
			ban.Source = ""
			if old, ok := g.state.Bans[ban.Prefix]; ok && old.Generation == ban.Generation && old.Until.After(ban.Until) {
				ban.Until = old.Until
			}
			next.Bans[ban.Prefix] = ban
		}
		for _, exemption := range chunk.Exemptions {
			key, _ := protocol.ExemptionKey(exemption.IP)
			exemption.IP = key
			next.Exemptions[exemption.IP] = exemption
		}
		if len(next.Bans) > masterBanLimit || len(next.Exemptions) > 100000 {
			return errors.New("dynamic snapshot capacity exceeded")
		}
	}
	localCount := 0
	for prefix, ban := range g.state.Bans {
		if source, ok := next.Sources[ban.Source]; ok && source.Generation == ban.Generation && ban.Until.After(time.Now()) {
			if _, exists := next.Bans[prefix]; !exists && localCount < sourceBanLimit {
				localCount++
				next.Bans[prefix] = ban
			}
		}
	}
	for prefix := range g.state.Bans {
		if _, exists := next.Bans[prefix]; !exists {
			g.resetAt[prefix] = time.Now().UTC()
		}
	}
	grants := make([]protocol.FirewallExemption, 0, len(next.Exemptions))
	for _, grant := range next.Exemptions {
		grants = append(grants, grant)
	}
	if err := g.markExemptionFormat(grants); err != nil {
		return err
	}
	previous := g.state
	g.state = next
	g.recountSourceBans()
	g.rebuildExemptionMasks()
	g.dirty = true
	if err = g.compact(); err != nil {
		if g.state.JournalEpoch == next.JournalEpoch {
			g.state = previous
			g.recountSourceBans()
			g.rebuildExemptionMasks()
		}
		return err
	}
	for _, name := range []string{"sync.json.gz", "sync.json"} {
		if err = os.Remove(g.file(name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
