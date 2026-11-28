package xray

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"google.golang.org/protobuf/proto"
)

func defaultOutboundTag(p *Prepared) string {
	if len(p.Core.Outbound) == 0 {
		return ""
	}
	return p.Core.Outbound[0].Tag
}

func sameOutbounds(a, b *Prepared) bool {
	if len(a.Outbounds) != len(b.Outbounds) || defaultOutboundTag(a) != defaultOutboundTag(b) {
		return false
	}
	for tag, out := range a.Outbounds {
		if !proto.Equal(out, b.Outbounds[tag]) {
			return false
		}
	}
	return true
}

func outboundReloadBlocker(old, next *Prepared) string {
	if sameOutbounds(old, next) {
		return ""
	}
	if defaultOutboundTag(next) == "" {
		return "there is no configured default outbound"
	}
	changed := map[string]bool{}
	for tag, cfg := range next.Outbounds {
		if !proto.Equal(old.Outbounds[tag], cfg) {
			changed[tag] = true
		}
	}
	for tag := range old.Outbounds {
		if next.Outbounds[tag] == nil {
			changed[tag] = true
			if routingMaySelect(next, tag) || nativeServiceSelectsOutbound(next, tag) ||
				(routingMaySelect(old, tag) || nativeServiceSelectsOutbound(old, tag)) && !pinMemberOutbound(old, tag) {
				return "a removed outbound may still be selected by routing or a native service"
			}
		}
	}
	for _, p := range []*Prepared{old, next} {
		for _, raw := range p.Native["outbounds"].([]any) {
			out := raw.(map[string]any)
			tag, _ := out["tag"].(string)
			dependencies, err := outboundDependencies(raw)
			if err != nil || changed[tag] && unsafeOutbound(raw, dependencies) {
				return "the changed outbound uses native mux, reverse, or chaining"
			}
			for _, dependency := range dependencies {
				if changed[dependency] {
					return "a changed outbound is used by a native dialer chain"
				}
			}
		}
	}
	return ""
}

// Typed member graphs use direct routing rules. The dispatcher pins those
// handlers before publishing a replacement. Keep the conservative barrier
// for code paths that can obtain tags outside ordinary field-rule dispatch.
func nativeServiceSelectsOutbound(p *Prepared, tag string) bool {
	if p.Native["api"] != nil || p.Native["reverse"] != nil {
		return true
	}
	for key, v := range p.Native {
		if v == nil || !strings.EqualFold(key, "observatory") && !strings.EqualFold(key, "burstObservatory") {
			continue
		}
		observer, ok := v.(map[string]any)
		if !ok {
			return true
		}
		for field, raw := range observer {
			if !strings.EqualFold(field, "subjectSelector") || raw == nil {
				continue
			}
			selectors, ok := raw.([]any)
			if !ok {
				return true
			}
			for _, value := range selectors {
				prefix, ok := value.(string)
				if !ok || strings.HasPrefix(tag, prefix) {
					return true
				}
			}
		}
	}
	// Native TUN DNS can resolve a route without our dispatcher adapter.
	inbounds, _ := p.Native["inbounds"].([]any)
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		if protocolName, _ := in["protocol"].(string); strings.EqualFold(protocolName, "tun") {
			return true
		}
	}
	return false
}

func pinMemberOutbound(p *Prepared, tag string) bool {
	return tag != defaultOutboundTag(p) && slices.Contains(p.Source.MemberOutbounds, tag) &&
		!nativeServiceSelectsOutbound(p, tag) && !routingIndirectlySelects(p, tag)
}

func routingMaySelect(p *Prepared, tag string) bool {
	if p.Router == nil {
		return false
	}
	for _, rule := range p.Router.Rule {
		if rule.GetTag() == tag {
			return true
		}
	}
	return routingIndirectlySelects(p, tag)
}

func routingIndirectlySelects(p *Prepared, tag string) bool {
	if p.Router == nil {
		return false
	}
	if p.Router.Script != "" {
		return true
	}
	for _, rule := range p.Router.BalancingRule {
		if rule.GetFallbackTag() == tag {
			return true
		}
		for _, selector := range rule.GetOutboundSelector() {
			if strings.HasPrefix(tag, selector) {
				return true
			}
		}
	}
	return false
}

// outboundUpdate starts changed concrete handlers before making them visible.
// Runtime serializes configured publications; the native API can still add or
// remove unrelated dynamic handlers through the public manager interfaces.
type outboundUpdate struct {
	manager          *managedManager
	original         *outboundTable
	previous         map[string]*managedOutbound
	created          map[string]*managedOutbound
	primaryTag       string
	publishedPrimary *managedOutbound
	stats            *Statistics
	published        bool
	committed        bool
}

func (r *Runtime) prepareOutboundUpdate(next *Prepared) (*outboundUpdate, error) {
	manager, ok := r.instance.GetFeature(outbound.ManagerType()).(*managedManager)
	if !ok {
		return nil, errors.New("managed outbound table is unavailable")
	}
	if err := manager.checkRouteHistory(r.current, next); err != nil {
		return nil, err
	}
	if sameOutbounds(r.current, next) {
		return nil, nil
	}
	stage := &outboundUpdate{manager: manager, original: manager.table.Load(), previous: make(map[string]*managedOutbound), created: make(map[string]*managedOutbound), primaryTag: defaultOutboundTag(next), stats: &r.stats}
	for tag, cfg := range next.Outbounds {
		if proto.Equal(r.current.Outbounds[tag], cfg) {
			continue
		}
		existing := stage.original.tagged[tag]
		if r.current.Outbounds[tag] == nil && existing != nil {
			stage.abort()
			return nil, fmt.Errorf("outbound tag %q is used by a dynamic handler", tag)
		}
		object, err := core.CreateObject(r.instance, proto.Clone(cfg))
		if err != nil {
			stage.abort()
			return nil, err
		}
		handler, ok := object.(outbound.Handler)
		if !ok {
			stage.abort()
			return nil, errors.New("invalid outbound handler")
		}
		stage.previous[tag] = existing
		stage.created[tag] = manager.newHandler(handler)
		if err := handler.Start(); err != nil {
			stage.abort()
			return nil, err
		}
	}
	for tag := range r.current.Outbounds {
		if next.Outbounds[tag] == nil {
			stage.previous[tag] = stage.original.tagged[tag]
		}
	}
	return stage, nil
}

func (m *managedManager) checkRouteHistory(current, next *Prepared) error {
	if sameOutbounds(current, next) && sameRouting(current, next) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var prefixes []string
	checked := make(map[string]bool)
	note := func(tag string) {
		if checked[tag] || current.Outbounds[tag] == nil {
			return
		}
		checked[tag] = true
		if _, tracked := m.routed[tag]; tracked || pinMemberOutbound(current, tag) {
			return
		}
		if m.routed == nil {
			m.routed = make(map[string]struct{})
		}
		m.routed[tag] = struct{}{}
	}
	if current.Router != nil {
		for _, rule := range current.Router.Rule {
			note(rule.GetTag())
		}
		for _, rule := range current.Router.BalancingRule {
			note(rule.GetFallbackTag())
			prefixes = append(prefixes, rule.GetOutboundSelector()...)
		}
		if current.Router.Script != "" {
			prefixes = []string{""}
		}
	}
	for tag := range current.Outbounds {
		for _, prefix := range prefixes {
			if strings.HasPrefix(tag, prefix) {
				note(tag)
				break
			}
		}
		// A dispatcher may still have a tag selected by a prior routing
		// generation even if a previous hot update removed that rule. The
		// set stays bounded by the configured outbound limit: these tags
		// cannot subsequently be removed from the configured table.
		if _, routed := m.routed[tag]; routed && next.Outbounds[tag] == nil {
			return fmt.Errorf("%w: a previously routed outbound may still be selected", ErrReloadUnsupported)
		}
	}
	return nil
}

func (u *outboundUpdate) publish() error {
	if u == nil {
		return nil
	}
	m := u.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	return u.publishLocked()
}

func (u *outboundUpdate) publishLocked() error {
	m := u.manager
	current := m.table.Load()
	for tag, prior := range u.previous {
		if current.tagged[tag] != prior {
			return fmt.Errorf("outbound tag %q changed during reload", tag)
		}
	}
	if m.closed || current.primary != u.original.primary {
		return errors.New("default outbound changed during reload")
	}
	next := current.clone()
	for tag := range u.previous {
		if candidate := u.created[tag]; candidate != nil {
			next.tagged[tag] = candidate
		} else {
			delete(next.tagged, tag)
		}
	}
	next.primary = next.tagged[u.primaryTag]
	if next.primary == nil {
		return errors.New("new default outbound is not available")
	}
	u.publishedPrimary = next.primary
	u.published = true
	m.store(next)
	return nil
}

func (u *outboundUpdate) commit() {
	if u == nil {
		return
	}
	u.committed = true
	m := u.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range u.previous {
		if h != nil {
			m.retire(h)
		}
	}
	u.stats.HandlerReplacements += uint64(len(u.created))
}

func (u *outboundUpdate) abort() {
	if u == nil || u.committed {
		return
	}
	if !u.published {
		for _, h := range u.created {
			_ = h.lifetime.close()
		}
		return
	}
	m := u.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.table.Load()
	next := current.clone()
	for tag, prior := range u.previous {
		// Do not undo a concurrent mutation by the native API.
		if current.tagged[tag] != u.created[tag] {
			continue
		}
		if prior == nil {
			delete(next.tagged, tag)
		} else {
			next.tagged[tag] = prior
		}
	}
	if current.primary == u.publishedPrimary {
		next.primary = u.original.primary
	}
	m.store(next)
	for _, h := range u.created {
		m.retire(h)
	}
}
