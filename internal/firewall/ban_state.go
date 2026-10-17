package firewall

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"go4.org/netipx"
)

type sourceState struct {
	protocol.FirewallSource
	Expired     bool `json:"expired,omitempty"`
	BaseExpired bool `json:"base_expired,omitempty"`
}
type banState struct {
	SourceRevision uint64                                `json:"source_revision"`
	MasterVersion  uint64                                `json:"master_version"`
	EventNamespace string                                `json:"event_namespace"`
	NextEvent      uint64                                `json:"next_event"`
	Revision       uint64                                `json:"revision"`
	Bans           map[string]protocol.FirewallBan       `json:"bans"`
	Exemptions     map[string]protocol.FirewallExemption `json:"exemptions"`
	Sources        map[string]sourceState                `json:"sources"`
	Events         map[string]protocol.FirewallEvent     `json:"events"`
	SnapshotID     string                                `json:"snapshot_id"`
	JournalEpoch   string                                `json:"journal_epoch"`
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
	mu             sync.Mutex
	dir            string
	state          banState
	manager        *Manager
	policy         atomic.Pointer[protocol.FirewallPolicy]
	hits           chan observedHit
	acks           chan []string
	kernelReady    atomic.Bool
	dropped        atomic.Uint64
	resetAt        map[string]time.Time
	eventOrder     []string
	eventStart     int
	windows        map[string]hitWindow
	indexes        map[string]*netipx.IPSet
	dirty          bool
	sourcesDirty   bool
	pendingJournal *journalRecord
	haveSnapshot   bool
	journalBytes   int64
	applying       bool
	kernelError    string
	compacted      time.Time
}

func emptyBans() banState {
	return banState{Bans: map[string]protocol.FirewallBan{}, Exemptions: map[string]protocol.FirewallExemption{}, Sources: map[string]sourceState{}, Events: map[string]protocol.FirewallEvent{}, JournalEpoch: state.ID(), EventNamespace: state.ID()}
}
func OpenGuard(dir string, manager *Manager) (*Guard, error) {
	g := &Guard{dir: dir, manager: manager, state: emptyBans(), hits: make(chan observedHit, 4096), acks: make(chan []string, 32), resetAt: map[string]time.Time{}, windows: map[string]hitWindow{}, indexes: map[string]*netipx.IPSet{}, dirty: true, sourcesDirty: true, compacted: time.Now()}
	if err := g.load(); err != nil {
		return nil, err
	}
	g.eventOrder = nil
	for id := range g.state.Events {
		g.eventOrder = append(g.eventOrder, id)
	}
	sort.Strings(g.eventOrder)
	if err := g.buildIndexes(); err != nil {
		return nil, err
	}
	return g, nil
}
func (g *Guard) Configure(policy protocol.FirewallPolicy) {
	if old := g.policy.Load(); old != nil && reflect.DeepEqual(*old, policy) {
		return
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
func (g *Guard) buildIndexes() error {
	g.indexes = map[string]*netipx.IPSet{}
	for id, source := range g.state.Sources {
		if source.Expired {
			continue
		}
		var builder netipx.IPSetBuilder
		for _, raw := range source.Prefixes {
			prefix, err := protocol.FirewallPrefix(raw)
			if err != nil {
				return err
			}
			builder.AddPrefix(prefix)
		}
		index, err := builder.IPSet()
		if err != nil {
			return err
		}
		g.indexes[id] = index
	}
	return nil
}
func (g *Guard) file(name string) string { return filepath.Join(g.dir, name) }
