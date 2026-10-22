package firewall

import (
	"net/netip"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func (g *Guard) exempt(ip netip.Addr, now time.Time) bool {
	if g.nodeIPs[ip.String()] || g.memberIPs[ip.String()].After(now) {
		return true
	}
	if g.state.Exemptions[ip.String()].Until.After(now) {
		return true
	}
	for mask := range g.exemptionMasks {
		bits := mask
		if ip.Is6() {
			if mask < 256 {
				continue
			}
			bits -= 256
		} else if mask >= 256 {
			continue
		}
		if g.state.Exemptions[netip.PrefixFrom(ip, bits).Masked().String()].Until.After(now) {
			return true
		}
	}
	return false
}
func (g *Guard) sourceBan(ip netip.Addr, now time.Time) (protocol.FirewallBan, bool) {
	g.rebuildSourceLookups()
	for i := range g.lookups {
		lookup := &g.lookups[i]
		id := lookup.id
		source := g.state.Sources[id]
		if !source.Until.After(now) || source.Expired {
			continue
		}
		contained, err := lookup.contains(ip)
		if err != nil {
			g.kernelError = "FIREWALL_SOURCE_UNAVAILABLE"
			continue
		}
		if contained {
			prefix, _ := protocol.FirewallPrefix(ip.String())
			return protocol.FirewallBan{Prefix: prefix.String(), Generation: source.Generation, Until: source.Until, RefreshSeconds: source.RefreshSeconds, Source: id}, true
		}
	}
	return protocol.FirewallBan{}, false
}

// processHits journals bounded deltas below any threshold. Only the master
// aggregates detection windows and creates bans; agents never extend them.
func (g *Guard) processHits(now time.Time) error {
	policy := g.policy.Load()
	if policy == nil || !policy.Protect || !policy.MasterControlled {
		return nil
	}
	for range 4096 {
		var hit observedHit
		select {
		case hit = <-g.hits:
		default:
			goto drained
		}
		if hit.rule == "blacklist" || g.exempt(hit.ip, hit.at) {
			continue
		}
		rule, enabled := policy.Rule(hit.rule)
		if !enabled {
			continue
		}
		if hit.rule == "source_match" {
			if _, found := g.sourceBan(hit.ip, hit.at); !found {
				continue
			}
		}
		key := hit.ip.String() + "|" + hit.rule
		window, known := g.windows[key]
		if !known && len(g.windows) >= 65536 {
			g.dropped.Add(1)
			continue
		}
		if known && !hit.at.Before(window.until) {
			g.dropped.Add(window.count)
			known = false
		}
		if !known {
			window = hitWindow{prefix: hit.ip.String(), first: hit.at, until: hit.at.Add(time.Duration(rule.WindowSeconds) * time.Second)}
		}
		window.count++
		window.last = hit.at
		g.windows[key] = window
	}
drained:
	record := journalRecord{}
	keys := make([]string, 0)
	for key, window := range g.windows {
		if len(record.Events)+len(g.state.Events) >= 4096 {
			break
		}
		if window.count == 0 {
			continue
		}
		split := strings.LastIndexByte(key, '|')
		record.Events = append(record.Events, protocol.FirewallEvent{Kind: "detected", IP: window.prefix, Rule: key[split+1:], Count: window.count, FirstSeen: window.first, Time: window.last})
		keys = append(keys, key)
	}
	if len(record.Events) == 0 {
		return nil
	}
	err := g.appendJournal(record)
	if err == nil || g.pendingJournal != nil {
		for _, key := range keys {
			delete(g.windows, key)
		}
	}
	return err
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
