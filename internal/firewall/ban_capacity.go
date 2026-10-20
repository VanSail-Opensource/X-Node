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
