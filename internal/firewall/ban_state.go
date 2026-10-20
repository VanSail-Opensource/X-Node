package firewall

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type sourceState struct {
	protocol.FirewallSource
	PrefixCount        int    `json:"prefix_count,omitempty"`
	PreviousGeneration string `json:"previous_generation,omitempty"`
	Expired            bool   `json:"expired,omitempty"`
	BaseExpired        bool   `json:"base_expired,omitempty"`
}
type banState struct {
	SourceMasterVersion uint64                                `json:"source_master_version"`
	SourceRevision      uint64                                `json:"source_revision"`
	MasterVersion       uint64                                `json:"master_version"`
	EventNamespace      string                                `json:"event_namespace"`
	NextEvent           uint64                                `json:"next_event"`
	Revision            uint64                                `json:"revision"`
	Bans                map[string]protocol.FirewallBan       `json:"bans"`
	Exemptions          map[string]protocol.FirewallExemption `json:"exemptions"`
	Sources             map[string]sourceState                `json:"sources"`
	Events              map[string]protocol.FirewallEvent     `json:"events"`
	SnapshotID          string                                `json:"snapshot_id"`
	JournalEpoch        string                                `json:"journal_epoch"`
}
type observedHit struct {
	ip   netip.Addr
	rule string
	at   time.Time
}
type hitWindow struct {
	prefix   string
	first    time.Time
	count    uint64
	reported bool
	until    time.Time
}

// Guard separates observations from durable, master-authorized restrictions.
// Hot inbound paths only enqueue bounded observations; all filesystem/kernel
// work runs outside Xray payload handling and the control socket reader.
type Guard struct {
	enforceRetryAt    time.Time
	enforceRetryDelay time.Duration
	lookupRevision    uint64
	lookups           []sourceLookup
	sourceBanCount    int
	sourceMu          sync.Mutex
	mu                sync.Mutex
	dir               string
	state             banState
	manager           *Manager
	policy            atomic.Pointer[protocol.FirewallPolicy]
	hits              chan observedHit
	acks              chan []string
	kernelReady       atomic.Bool
	dropped           atomic.Uint64
	exemptionMasks    map[int]bool
	resetAt           map[string]time.Time
	eventOrder        []string
	eventStart        int
	windows           map[string]hitWindow
	dirty             bool
	sourcesDirty      bool
	pendingJournal    *journalRecord
	legacySources     bool
	retainBulk        bool
	haveSnapshot      bool
	journalBytes      int64
	applying          bool
	kernelError       string
	compacted         time.Time
}

func emptyBans() banState {
	return banState{Bans: map[string]protocol.FirewallBan{}, Exemptions: map[string]protocol.FirewallExemption{}, Sources: map[string]sourceState{}, Events: map[string]protocol.FirewallEvent{}, JournalEpoch: state.ID(), EventNamespace: state.ID()}
}
func OpenGuard(dir string, manager *Manager) (*Guard, error) {
	g := &Guard{dir: dir, manager: manager, state: emptyBans(), hits: make(chan observedHit, 4096), acks: make(chan []string, 32), resetAt: map[string]time.Time{}, windows: map[string]hitWindow{}, dirty: true, sourcesDirty: true, compacted: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, err := g.lockBulk(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err = g.cleanupBulkScratch(); err != nil {
		return nil, err
	}
	if err := g.load(); err != nil {
		return nil, err
	}
	g.eventOrder = nil
	for id := range g.state.Events {
		g.eventOrder = append(g.eventOrder, id)
	}
	sort.Strings(g.eventOrder)
	if err := g.prepareStoredSources(); err != nil {
		return nil, err
	}
	trimmed := trimStoredBans(g.state.Bans, false, masterBanLimit) + trimStoredBans(g.state.Bans, true, sourceBanLimit)
	if trimmed > 0 {
		g.dropped.Add(trimmed)
		if err := g.compact(); err != nil {
			return nil, err
		}
	}
	g.recountSourceBans()
	g.rebuildExemptionMasks()
	if g.legacySources && !g.sourceUpgradePending() {
		if err := g.compact(); err != nil {
			return nil, err
		}
	}
	return g, nil
}
func (g *Guard) Configure(policy protocol.FirewallPolicy) {
	if old := g.policy.Load(); old != nil && reflect.DeepEqual(*old, policy) {
		return
	}
	if old := g.policy.Load(); old != nil && old.SourceGeoIP != nil && (policy.SourceGeoIP == nil || old.SourceGeoIP.Generation != policy.SourceGeoIP.Generation) {
		raw, _ := json.Marshal(map[string]string{"generation": old.SourceGeoIP.Generation})
		if err := state.AtomicWrite(g.file("geoip-previous.json"), raw, 0600); err != nil {
			g.mu.Lock()
			g.retainBulk = true
			g.mu.Unlock()
		}
	}
	copy := protocol.Clone(policy)
	g.policy.Store(&copy)
	g.mu.Lock()
	g.dirty = true
	g.sourcesDirty = true
	g.state.Revision++
	g.state.SourceRevision++
	g.mu.Unlock()
}
func (g *Guard) Observe(ip netip.Addr, rule string) {
	p := g.policy.Load()
	if p == nil || !p.Enabled || !p.MasterControlled && rule != "blacklist" {
		return
	}
	if rule != "blacklist" {
		if _, enabled := p.Rule(rule); !enabled {
			return
		}
	}
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return
	}
	select {
	case g.hits <- observedHit{ip: ip.Unmap(), rule: rule, at: time.Now().UTC()}:
	default:
		g.dropped.Add(1)
	}
}
func (g *Guard) Acknowledge(ids []string) {
	if len(ids) > 512 {
		return
	}
	select {
	case g.acks <- append([]string(nil), ids...):
	default:
		g.dropped.Add(1)
	}
}
func (g *Guard) prepareStoredSources() error {
	for id, source := range g.state.Sources {
		if source.Expired {
			continue
		}
		if err := g.migrateSource(&source); err != nil {
			return err
		}
		g.state.Sources[id] = source
	}
	return nil
}
func (g *Guard) file(name string) string { return filepath.Join(g.dir, name) }
