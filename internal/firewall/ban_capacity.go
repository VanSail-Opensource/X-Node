package firewall

import (
	"errors"
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const (
	banSetSize     = 1 << 20
	masterBanLimit = 1_000_000
	sourceBanLimit = banSetSize - masterBanLimit
	banSetV4       = "banned_v4_v2"
	banSetV6       = "banned_v6_64_v2"
)

// Source is reserved for locally refreshed source inventory entries. Master
// commands are normalized at admission so a source ID cannot change priority.
func boundedBans(bans []protocol.FirewallBan, limit int) ([]protocol.FirewallBan, uint64) {
	if len(bans) <= limit {
		return bans, 0
	}
	sort.Slice(bans, func(i, j int) bool {
		a, b := bans[i], bans[j]
		if (a.Source == "") != (b.Source == "") {
			return a.Source == ""
		}
		if !a.Until.Equal(b.Until) {
			return a.Until.After(b.Until)
		}
		return a.Prefix < b.Prefix
	})
	return bans[:limit], uint64(len(bans) - limit)
}

func (g *Guard) admitMasterBans(record journalRecord) error {
	count := len(g.state.Bans) - g.sourceBanCount
	removed := make(map[string]bool, len(record.Remove))
	for _, prefix := range record.Remove {
		if !removed[prefix] {
			if old, ok := g.state.Bans[prefix]; ok && old.Source == "" {
				count--
			}
		}
		removed[prefix] = true
	}
	seen := make(map[string]bool, len(record.Bans))
	for _, ban := range record.Bans {
		old, exists := g.state.Bans[ban.Prefix]
		if !seen[ban.Prefix] && !removed[ban.Prefix] && (!exists || old.Source != "") {
			count++
		}
		seen[ban.Prefix] = true
	}
	if count > masterBanLimit {
		return errors.New("master ban capacity exceeded")
	}
	return nil
}

func (g *Guard) enforcementResult(err error, now time.Time) {
	if err == nil {
		g.enforceRetryAt, g.enforceRetryDelay = time.Time{}, 0
		return
	}
	if g.enforceRetryDelay == 0 {
		g.enforceRetryDelay = time.Second
	} else {
		g.enforceRetryDelay = min(time.Minute, g.enforceRetryDelay*2)
	}
	g.enforceRetryAt = now.Add(g.enforceRetryDelay)
}

func (g *Guard) recountSourceBans() {
	g.sourceBanCount = 0
	for _, ban := range g.state.Bans {
		if ban.Source != "" {
			g.sourceBanCount++
		}
	}
}

func (g *Guard) enforcementDue(now time.Time) bool { return !now.Before(g.enforceRetryAt) }

// Old releases did not bound locally refreshed bans. Trim persisted state once
// on startup as well as enforcing admission limits for new commands and hits.
func trimStoredBans(bans map[string]protocol.FirewallBan, source bool, limit int) uint64 {
	count := 0
	for _, ban := range bans {
		if (ban.Source != "") == source {
			count++
		}
	}
	if count <= limit {
		return 0
	}
	items := make([]protocol.FirewallBan, 0, count)
	for _, ban := range bans {
		if (ban.Source != "") == source {
			items = append(items, ban)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].Until.Equal(items[j].Until) {
			return items[i].Until.After(items[j].Until)
		}
		return items[i].Prefix < items[j].Prefix
	})
	for _, ban := range items[limit:] {
		delete(bans, ban.Prefix)
	}
	return uint64(count - limit)
}
