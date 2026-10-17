package firewall

import (
	"net/netip"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func (g *Guard) exempt(ip netip.Addr, now time.Time) bool {
	return g.state.Exemptions[ip.String()].Until.After(now)
}
func (g *Guard) sourceBan(ip netip.Addr, now time.Time) (protocol.FirewallBan, bool) {
	for id, index := range g.indexes {
		source := g.state.Sources[id]
		if source.Until.After(now) && index.Contains(ip) {
			prefix, _ := protocol.FirewallPrefix(ip.String())
			return protocol.FirewallBan{Prefix: prefix.String(), Generation: source.Generation, Until: source.Until, RefreshSeconds: source.RefreshSeconds, Source: id}, true
		}
	}
	return protocol.FirewallBan{}, false
}
func (g *Guard) processHits(now time.Time) error {
	policy := g.policy.Load()
	if policy == nil {
		return nil
	}
	updates := map[string]protocol.FirewallBan{}
	record := journalRecord{}
	for range 4096 {
		var hit observedHit
		select {
		case hit = <-g.hits:
		default:
			goto drained
		}
		if g.exempt(hit.ip, hit.at) {
			continue
		}
		prefix, _ := protocol.FirewallPrefix(hit.ip.String())
		ban, exists := updates[prefix.String()]
		if !exists {
			ban, exists = g.state.Bans[prefix.String()]
		}
		if !exists || !ban.Until.After(hit.at) {
			ban, exists = g.sourceBan(hit.ip, hit.at)
		}
		if exists && ban.Until.After(hit.at) {
			until := hit.at.Add(time.Duration(ban.RefreshSeconds) * time.Second)
			if until.After(ban.Until) {
				ban.Until = until
				updates[ban.Prefix] = ban
			}
			continue
		}
		rule, enabled := policy.Rule(hit.rule)
		if !enabled {
			continue
		}
		key := hit.ip.String() + "|" + hit.rule
		window, known := g.windows[key]
		if !known && len(g.windows) >= 65536 {
			g.dropped.Add(1)
			continue
		}
		if !known || window.first.Before(g.resetAt[prefix.String()]) || !hit.at.Before(window.first.Add(time.Duration(rule.WindowSeconds)*time.Second)) {
			window = hitWindow{prefix: prefix.String(), first: hit.at, until: hit.at.Add(time.Duration(rule.WindowSeconds) * time.Second)}
		}
		window.count++
		if !window.reported && window.count >= uint64(rule.Threshold) && len(g.state.Events)+len(record.Events) < 4096 {
			record.Events = append(record.Events, protocol.FirewallEvent{ID: state.ID(), Kind: "detected", IP: hit.ip.String(), Rule: hit.rule, Count: window.count, FirstSeen: window.first, Time: hit.at})
			window.reported = true
		}
		g.windows[key] = window
	}
drained:
	for _, ban := range updates {
		record.Bans = append(record.Bans, ban)
	}
	for key, window := range g.windows {
		if !window.until.After(now) || g.state.Bans[window.prefix].Until.After(now) {
			delete(g.windows, key)
		}
	}
	if len(record.Bans) == 0 && len(record.Events) == 0 {
		return nil
	}
	return g.appendJournal(record)
}

func (g *Guard) expire(now time.Time) error {
	record := journalRecord{}
	for prefix, ban := range g.state.Bans {
		if len(record.Remove) >= 4096 {
			break
		}
		if ban.Until.After(now) {
			continue
		}
		record.Remove = append(record.Remove, prefix)
		record.Events = append(record.Events, protocol.FirewallEvent{ID: state.ID(), Kind: "expired", IP: prefix, Prefix: prefix, Generation: ban.Generation, Rule: ban.Source, Time: now})
	}
	for ip, exemption := range g.state.Exemptions {
		if !exemption.Until.After(now) {
			record.RemoveExemptions = append(record.RemoveExemptions, ip)
		}
	}
	for id, source := range g.state.Sources {
		if source.Until.After(now) || source.Expired {
			continue
		}
		if !source.BaseExpired {
			record.BaseExpiredSources = append(record.BaseExpiredSources, id)
			g.sourcesDirty = true
		}
		retained := false
		for _, ban := range g.state.Bans {
			if ban.Source == id && ban.Generation == source.Generation && ban.Until.After(now) {
				retained = true
				break
			}
		}
		if retained {
			continue
		}
		record.ExpiredSources = append(record.ExpiredSources, id)
		record.Events = append(record.Events, protocol.FirewallEvent{ID: state.ID(), Kind: "source_expired", Generation: source.Generation, Rule: id, Time: now})
	}
	if len(record.Remove)+len(record.RemoveExemptions)+len(record.ExpiredSources)+len(record.BaseExpiredSources) == 0 {
		return nil
	}
	return g.appendJournal(record)
}

func (g *Guard) pendingEvents(limit int) []protocol.FirewallEvent {
	for g.eventStart < len(g.eventOrder) {
		if _, exists := g.state.Events[g.eventOrder[g.eventStart]]; exists {
			break
		}
		g.eventStart++
	}
	if g.eventStart > 4096 && g.eventStart*2 >= len(g.eventOrder) {
		g.eventOrder = append([]string(nil), g.eventOrder[g.eventStart:]...)
		g.eventStart = 0
	}
	events := make([]protocol.FirewallEvent, 0, limit)
	for _, id := range g.eventOrder[g.eventStart:] {
		if event, ok := g.state.Events[id]; ok {
			events = append(events, event)
			if len(events) == limit {
				break
			}
		}
	}
	return events
}
