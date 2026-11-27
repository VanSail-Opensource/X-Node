package xray

import (
	"context"
	"errors"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/outbound"
)

// Xray's public Manager does not replace a set of handlers atomically. The
// serving manager publishes one immutable lookup and default snapshot instead.
type managedManager struct {
	bridge          *integration
	mu              sync.Mutex
	table           atomic.Pointer[outboundTable]
	retired         map[*outboundLifetime]struct{}
	routed          map[string]struct{}
	running, closed bool
}

type outboundTable struct {
	tagged   map[string]*managedOutbound
	untagged []*managedOutbound
	primary  *managedOutbound
	tags     []string
	selected sync.Map
}

func (t *outboundTable) clone() *outboundTable {
	return &outboundTable{tagged: maps.Clone(t.tagged), untagged: slices.Clone(t.untagged), primary: t.primary}
}

func (t *outboundTable) handlers() []*managedOutbound {
	handlers := make([]*managedOutbound, 0, len(t.untagged)+len(t.tagged))
	handlers = append(handlers, t.untagged...)
	for _, h := range t.tagged {
		handlers = append(handlers, h)
	}
	return handlers
}

type outboundLifetime struct {
	manager *managedManager
	native  outbound.Handler
	once    sync.Once
	err     error
}

func (l *outboundLifetime) close() error {
	l.once.Do(func() { l.err = l.native.Close() })
	return l.err
}

func closeRetiredOutbound(l *outboundLifetime) {
	_ = l.close()
	l.manager.mu.Lock()
	delete(l.manager.retired, l)
	l.manager.mu.Unlock()
}

func init() {
	common.Must(common.RegisterConfig((*ManagerConfig)(nil), func(ctx context.Context, _ any) (any, error) {
		m := &managedManager{bridge: ctx.Value(bridgeKey{}).(*integration), retired: make(map[*outboundLifetime]struct{})}
		m.store(&outboundTable{tagged: make(map[string]*managedOutbound)})
		return m, nil
	}))
}

func (m *managedManager) newHandler(h outbound.Handler) *managedOutbound {
	return &managedOutbound{Handler: h, bridge: m.bridge, lifetime: &outboundLifetime{manager: m, native: h}}
}

func (m *managedManager) retire(h *managedOutbound) {
	// GetHandler can return a handler that has not entered Dispatch yet. Do
	// not close it based on an in-flight dispatch count: the native reader
	// itself pins the wrapper, and Dispatch explicitly keeps it alive.
	if _, exists := m.retired[h.lifetime]; exists {
		return
	}
	m.retired[h.lifetime] = struct{}{}
	runtime.AddCleanup(h, closeRetiredOutbound, h.lifetime)
}

func (m *managedManager) store(t *outboundTable) {
	t.tags = slices.Sorted(maps.Keys(t.tagged))
	m.table.Store(t)
}

func (*managedManager) Type() any { return outbound.ManagerType() }

func (m *managedManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("outbound manager is closed")
	}
	for _, h := range m.table.Load().handlers() {
		if err := h.Start(); err != nil {
			return err
		}
	}
	m.running = true
	return nil
}

func (m *managedManager) Close() error {
	m.mu.Lock()
	m.closed, m.running = true, false
	lifetimes := make([]*outboundLifetime, 0, len(m.retired)+len(m.table.Load().tagged))
	for l := range m.retired {
		lifetimes = append(lifetimes, l)
	}
	for _, h := range m.table.Load().handlers() {
		lifetimes = append(lifetimes, h.lifetime)
	}
	m.store(&outboundTable{tagged: make(map[string]*managedOutbound)})
	m.mu.Unlock()
	var errs []error
	for _, l := range lifetimes {
		errs = append(errs, l.close())
	}
	return errors.Join(errs...)
}

func (m *managedManager) GetDefaultHandler() outbound.Handler {
	if h := m.table.Load().primary; h != nil {
		return h
	}
	return nil
}

func (m *managedManager) GetHandler(tag string) outbound.Handler {
	if h := m.table.Load().tagged[tag]; h != nil {
		return h
	}
	return nil
}

func (m *managedManager) AddHandler(_ context.Context, native outbound.Handler) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("outbound manager is closed")
	}
	old := m.table.Load()
	tag := native.Tag()
	if tag != "" && old.tagged[tag] != nil {
		m.mu.Unlock()
		return errors.New("outbound tag already exists: " + tag)
	}
	if m.running {
		if err := native.Start(); err != nil {
			m.mu.Unlock()
			_ = native.Close()
			return err
		}
	}
	next := old.clone()
	h := m.newHandler(native)
	if tag == "" {
		next.untagged = append(next.untagged, h)
	} else {
		next.tagged[tag] = h
	}
	if next.primary == nil {
		next.primary = h
	}
	m.store(next)
	m.mu.Unlock()
	return nil
}

func (m *managedManager) RemoveHandler(_ context.Context, tag string) error {
	if tag == "" {
		return common.ErrNoClue
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.table.Load()
	h := old.tagged[tag]
	if h == nil {
		return nil
	}
	next := old.clone()
	delete(next.tagged, tag)
	if next.primary == h {
		next.primary = nil
	}
	m.store(next)
	m.retire(h)
	return nil
}

func (m *managedManager) ListHandlers(_ context.Context) []outbound.Handler {
	handlers := m.table.Load().handlers()
	result := make([]outbound.Handler, len(handlers))
	for i, h := range handlers {
		result[i] = h
	}
	return result
}

// Select preserves the native prefix match and sorted tag order. A cache is
// tied to one immutable table and cannot race with mutations to another table.
func (m *managedManager) Select(selectors []string) []string {
	table := m.table.Load()
	key := strings.Join(selectors, "\x00")
	cacheable := len(selectors) > 0 && strings.Count(key, "\x00") == len(selectors)-1
	if cacheable {
		if cached, ok := table.selected.Load(key); ok {
			return cached.([]string)
		}
	}
	var result []string
	for _, tag := range table.tags {
		for _, selector := range selectors {
			if strings.HasPrefix(tag, selector) {
				result = append(result, tag)
				break
			}
		}
	}
	if cacheable {
		table.selected.Store(key, result)
	}
	return result
}

var (
	_ outbound.Manager         = (*managedManager)(nil)
	_ outbound.HandlerSelector = (*managedManager)(nil)
)
