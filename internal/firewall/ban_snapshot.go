package firewall

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"io"
	"net/netip"
	"os"
	"time"
)

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
	next.SourceRevision = g.state.SourceRevision + 1
	sourcesComplete := false
	removeSources := map[string]bool{}
	next.Revision = g.state.Revision + 1
	next.EventNamespace, next.NextEvent = g.state.EventNamespace, g.state.NextEvent
	next.SnapshotID = id
	next.Events = g.state.Events
	seen := map[int]bool{}
	decoder := json.NewDecoder(io.LimitReader(reader, maxBanStateBytes+1))
	for {
		var chunk protocol.FirewallUpdate
		if err = decoder.Decode(&chunk); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if chunk.SnapshotID != id || chunk.Version != version {
			return errors.New("firewall staged generation differs")
		}
		if seen[chunk.Index] {
			continue
		}
		seen[chunk.Index] = true
		if chunk.SourcesComplete {
			sourcesComplete = true
		}
		for _, sourceID := range chunk.RemoveSources {
			removeSources[sourceID] = true
		}
		for _, ban := range chunk.Bans {
			prefix, _ := protocol.FirewallPrefix(ban.Prefix)
			ban.Prefix = prefix.String()
			if old, ok := g.state.Bans[ban.Prefix]; ok && old.Generation == ban.Generation && old.Until.After(ban.Until) {
				ban.Until = old.Until
			}
			next.Bans[ban.Prefix] = ban
		}
		for _, exemption := range chunk.Exemptions {
			ip, _ := netip.ParseAddr(exemption.IP)
			exemption.IP = ip.Unmap().String()
			next.Exemptions[exemption.IP] = exemption
		}
		for _, source := range chunk.Sources {
			if source.Reference {
				old, exists := g.state.Sources[source.ID]
				if !exists || old.Generation != source.Generation || !old.Until.Equal(source.Until) {
					return errors.New("full source snapshot is required")
				}
				next.Sources[source.ID] = old
				continue
			}
			current, ok := next.Sources[source.ID]
			if ok && (current.Generation != source.Generation || !current.Until.Equal(source.Until)) {
				return errors.New("inconsistent source snapshot chunks")
			}
			current.FirewallSource.ID, current.Generation, current.Until, current.RefreshSeconds = source.ID, source.Generation, source.Until, source.RefreshSeconds
			current.Prefixes = append(current.Prefixes, source.Prefixes...)
			next.Sources[source.ID] = current
		}
		if len(next.Bans) > 1000000 || len(next.Exemptions) > 100000 || len(next.Sources) > 128 {
			return errors.New("firewall snapshot capacity exceeded")
		}
	}
	if !sourcesComplete {
		for sourceID, source := range g.state.Sources {
			if _, exists := next.Sources[sourceID]; !exists {
				next.Sources[sourceID] = source
			}
		}
	}
	for sourceID := range removeSources {
		delete(next.Sources, sourceID)
	}
	for prefix, ban := range g.state.Bans {
		if source, ok := next.Sources[ban.Source]; ok && ban.Generation == source.Generation && ban.Until.After(time.Now()) {
			if _, exists := next.Bans[prefix]; !exists {
				next.Bans[prefix] = ban
			}
		}
	}
	for sourceID, source := range next.Sources {
		if old, ok := g.state.Sources[sourceID]; ok && old.Generation == source.Generation {
			source.Expired, source.BaseExpired = old.Expired, old.BaseExpired
			next.Sources[sourceID] = source
		}
	}
	for prefix := range g.state.Bans {
		if _, exists := next.Bans[prefix]; !exists {
			g.resetAt[prefix] = time.Now().UTC()
		}
	}
	previous, indexes := g.state, g.indexes
	g.state = next
	if err = g.buildIndexes(); err != nil {
		g.state = previous
		g.indexes = indexes
		return err
	}
	g.dirty = true
	g.sourcesDirty = true
	if err = g.compact(); err != nil {
		if g.state.JournalEpoch == next.JournalEpoch {
			g.state = previous
			g.indexes = indexes
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
