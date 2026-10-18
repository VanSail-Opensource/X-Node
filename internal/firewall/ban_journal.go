package firewall

import (
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"time"
)

const maxBanStateBytes = 512 << 20

type journalRecord struct {
	SourceRevision     uint64                       `json:"source_revision"`
	MasterVersion      uint64                       `json:"master_version"`
	Revision           uint64                       `json:"revision"`
	NextEvent          uint64                       `json:"next_event"`
	SnapshotID         string                       `json:"snapshot_id,omitempty"`
	Epoch              string                       `json:"epoch"`
	Bans               []protocol.FirewallBan       `json:"bans,omitempty"`
	Exemptions         []protocol.FirewallExemption `json:"exemptions,omitempty"`
	Events             []protocol.FirewallEvent     `json:"events,omitempty"`
	Ack                []string                     `json:"ack,omitempty"`
	Remove             []string                     `json:"remove,omitempty"`
	RemoveExemptions   []string                     `json:"remove_exemptions,omitempty"`
	ExpiredSources     []string                     `json:"expired_sources,omitempty"`
	BaseExpiredSources []string                     `json:"base_expired_sources,omitempty"`
}

func (g *Guard) applyRecord(record journalRecord) {
	if record.SourceRevision > g.state.SourceRevision {
		g.state.SourceRevision = record.SourceRevision
	}
	if record.MasterVersion > g.state.MasterVersion {
		g.state.MasterVersion = record.MasterVersion
	}
	if record.Revision > g.state.Revision {
		g.state.Revision = record.Revision
	}
	if record.NextEvent > g.state.NextEvent {
		g.state.NextEvent = record.NextEvent
	}
	if record.SnapshotID != "" {
		g.state.SnapshotID = record.SnapshotID
	}
	for _, ban := range record.Bans {
		g.state.Bans[ban.Prefix] = ban
	}
	for _, item := range record.Exemptions {
		g.state.Exemptions[item.IP] = item
	}
	if len(record.Exemptions) > 0 || len(record.RemoveExemptions) > 0 {
		defer g.rebuildExemptionMasks()
	}
	for _, event := range record.Events {
		if _, exists := g.state.Events[event.ID]; !exists {
			g.eventOrder = append(g.eventOrder, event.ID)
		}
		g.state.Events[event.ID] = event
	}
	for _, prefix := range record.Remove {
		delete(g.state.Bans, prefix)
		g.resetAt[prefix] = time.Now().UTC()
	}
	for _, ip := range record.RemoveExemptions {
		delete(g.state.Exemptions, ip)
	}
	for _, id := range record.ExpiredSources {
		source := g.state.Sources[id]
		source.Expired = true
		g.state.Sources[id] = source
	}
	for _, id := range record.BaseExpiredSources {
		source := g.state.Sources[id]
		source.BaseExpired = true
		g.state.Sources[id] = source
	}
	if len(g.resetAt) > 65536 {
		clear(g.resetAt)
		clear(g.windows)
	}
	for _, id := range record.Ack {
		if event, ok := g.state.Events[id]; ok && event.Kind == "source_expired" {
			if source, exists := g.state.Sources[event.Rule]; exists && source.Generation == event.Generation {
				delete(g.state.Sources, event.Rule)
			}
		}
		delete(g.state.Events, id)
	}
}
