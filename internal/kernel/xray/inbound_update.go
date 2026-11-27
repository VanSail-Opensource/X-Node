package xray

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

type inboundGate struct {
	tag       string
	auxiliary bool
	ready     chan struct{}
	committed bool // published by closing ready
}

func (g *inboundGate) await(ctx context.Context) bool {
	select {
	case <-g.ready:
		return g.committed
	case <-ctx.Done():
		return false
	}
}

type gatedInbound struct {
	proxy.Inbound
	gate *inboundGate
}

// AddHandler closes a handler if Start fails, but not if a dynamic handler
// already owns the tag. The staging caller may close it in either case.
type stagedInboundHandler struct {
	inbound.Handler
	close sync.Once
	err   error
}

func (h *stagedInboundHandler) Close() error {
	h.close.Do(func() { h.err = h.Handler.Close() })
	return h.err
}

func (h *stagedInboundHandler) GetInbound() proxy.Inbound {
	return h.Handler.(proxy.GetInbound).GetInbound()
}

func (h *gatedInbound) Close() error { return common.Close(h.Inbound) }
func (h *gatedInbound) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if !h.gate.await(ctx) {
		return net.ErrClosed
	}
	return h.Inbound.Process(ctx, network, conn, dispatcher)
}

type inboundSwap struct {
	handler *observedInbound
	next    *inboundGeneration
}

type inboundUpdate struct {
	runtime  *Runtime
	ctx      context.Context
	next     *Prepared
	manager  inbound.Manager
	added    []*inboundGate
	removed  []string
	swaps    []inboundSwap
	rollback []func() error
	finished bool
}

func (p *inboundUpdate) abort() {
	if p == nil || p.finished {
		return
	}
	p.finished = true
	for i := len(p.rollback) - 1; i >= 0; i-- {
		_ = p.rollback[i]()
	}
	for _, gate := range p.added {
		close(gate.ready)
		_ = p.manager.RemoveHandler(p.ctx, gate.tag)
	}
	for _, swap := range p.swaps {
		_ = common.Close(swap.next.Inbound)
	}
}

func (p *inboundUpdate) commit() {
	if p.finished {
		return
	}
	p.finished = true
	r := p.runtime
	if !maps.Equal(r.current.Epochs, p.next.Epochs) {
		r.registry.SetInboundEpochs(p.next.Epochs)
	}
	if !maps.Equal(r.current.Auxiliary, p.next.Auxiliary) {
		r.bridge.setAuxiliary(p.next.Auxiliary)
	}
	for _, swap := range p.swaps {
		_ = swap.handler.replace(swap.next)
	}
	for _, gate := range p.added {
		gate.committed = true
		close(gate.ready)
	}
	for _, tag := range p.removed {
		// The authorization update already removed access to this endpoint.
		_ = p.manager.RemoveHandler(p.ctx, tag)
	}
	r.stats.HandlerReplacements += uint64(len(p.added))
}

// prepareInboundUpdate leaves serving sockets and their existing proxies alone.
// Added sockets are staged on unused endpoints and cannot dispatch before commit.
func (r *Runtime) prepareInboundUpdate(ctx context.Context, next *Prepared) (_ *inboundUpdate, result error) {
	manager := r.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	plan := &inboundUpdate{runtime: r, ctx: ctx, next: next, manager: manager}
	defer func() {
		if result != nil {
			plan.abort()
		}
	}()
	var additions []*core.InboundHandlerConfig
	var accounts []inboundAccountUpdate
	for _, cfg := range next.Core.Inbound {
		tag := cfg.Tag
		old := r.current.Inbounds[tag]
		if old == nil {
			if err := safeNewEndpoint(cfg, r.current.Core.Inbound, next.Core.Inbound); err != nil {
				return nil, err
			}
			if !next.Auxiliary[tag] && cfg.ProxySettings.Type != serial.GetMessageType(&InboundConfig{}) {
				return nil, fmt.Errorf("%w: native inbound %q cannot stage its transport while serving", ErrReloadUnsupported, tag)
			}
			additions = append(additions, cfg)
			continue
		}
		if proto.Equal(old, cfg) {
			continue
		}
		if !proto.Equal(old.ReceiverSettings, cfg.ReceiverSettings) || r.current.Auxiliary[tag] || next.Auxiliary[tag] {
			return nil, fmt.Errorf("%w: native inbound %q receiver cannot be hot-reloaded", ErrReloadUnsupported, tag)
		}
		handler, err := manager.GetHandler(ctx, tag)
		if err != nil {
			return nil, fmt.Errorf("native inbound %q is no longer serving: %w", tag, err)
		}
		getter, ok := handler.(proxy.GetInbound)
		if !ok {
			return nil, fmt.Errorf("native inbound %q has no live proxy", tag)
		}
		live := getter.GetInbound()
		if observed, ok := live.(*observedInbound); ok {
			swap, err := prepareInboundSwap(observed, old, cfg)
			if err != nil {
				return nil, fmt.Errorf("native inbound %q: %w", tag, err)
			}
			if swap != nil {
				plan.swaps = append(plan.swaps, inboundSwap{observed, swap})
				continue
			}
		}
		// Do not replace stateful validators and replay filters, including
		// Hysteria's validator, which is also retained by the transport hub.
		users, ok := live.(proxy.UserManager)
		if !ok || r.current.InboundBase[tag] != next.InboundBase[tag] {
			return nil, fmt.Errorf("%w: native inbound %q proxy cannot be hot-reloaded", ErrReloadUnsupported, tag)
		}
		diff, err := prepareAccounts(ctx, users, cfg)
		if err != nil {
			return nil, fmt.Errorf("native inbound %q: %w", tag, err)
		}
		accounts = append(accounts, diff)
	}
	for tag := range r.current.Inbounds {
		if next.Inbounds[tag] == nil {
			if r.current.Auxiliary[tag] {
				return nil, fmt.Errorf("%w: native inbound %q cannot drain untracked forwarding", ErrReloadUnsupported, tag)
			}
			plan.removed = append(plan.removed, tag)
		}
	}
	for _, cfg := range additions {
		gate := &inboundGate{tag: cfg.Tag, auxiliary: next.Auxiliary[cfg.Tag], ready: make(chan struct{})}
		if err := r.stageInbound(ctx, manager, cfg, gate); err != nil {
			close(gate.ready)
			return nil, err
		}
		plan.added = append(plan.added, gate)
	}
	for _, change := range accounts {
		undo, err := change.apply(ctx)
		plan.rollback = append(plan.rollback, undo)
		if err != nil {
			return nil, err
		}
	}
	return plan, nil
}

func (r *Runtime) stageInbound(ctx context.Context, manager inbound.Manager, cfg *core.InboundHandlerConfig, gate *inboundGate) error {
	managed, err := r.newStagedInbound(cfg, gate)
	if err != nil {
		return err
	}
	if err := manager.AddHandler(ctx, managed); err != nil {
		_ = managed.Close()
		return fmt.Errorf("native inbound %q listener activation failed: %w", cfg.Tag, err)
	}
	return nil
}

func (r *Runtime) newStagedInbound(cfg *core.InboundHandlerConfig, gate *inboundGate) (*stagedInboundHandler, error) {
	staged := proto.Clone(cfg).(*core.InboundHandlerConfig)
	if gate.auxiliary {
		staged.ProxySettings = serial.ToTypedMessage(&InboundConfig{
			NativeType: staged.ProxySettings.Type, NativeValue: staged.ProxySettings.Value, Tag: cfg.Tag,
		})
	}
	r.bridge.inboundGate.Store(gate)
	object, err := core.CreateObject(r.instance, staged)
	r.bridge.inboundGate.Store(nil)
	if err != nil {
		return nil, err
	}
	handler, ok := object.(inbound.Handler)
	if !ok {
		_ = common.Close(object)
		return nil, errors.New("invalid native inbound handler")
	}
	if _, ok := handler.(proxy.GetInbound); !ok {
		_ = common.Close(handler)
		return nil, errors.New("native inbound handler cannot expose its proxy")
	}
	return &stagedInboundHandler{Handler: handler}, nil
}

func prepareInboundSwap(h *observedInbound, old, next *core.InboundHandlerConfig) (*inboundGeneration, error) {
	oldConfig, err := old.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	nextConfig, err := next.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	a, aOK := oldConfig.(*InboundConfig)
	b, bOK := nextConfig.(*InboundConfig)
	if !aOK || !bOK || a.NativeType != b.NativeType || a.Reality != b.Reality {
		return nil, nil
	}
	for _, cfg := range []*InboundConfig{a, b} {
		value, err := cfg.native().GetInstance()
		if err != nil {
			return nil, err
		}
		switch value := value.(type) {
		case *trojan.ServerConfig:
		case *vlessin.Config:
			if value.Decryption != "" && value.Decryption != "none" {
				return nil, nil
			}
			for _, user := range value.Users {
				m, err := user.ToMemoryUser()
				if err != nil {
					return nil, err
				}
				if account, ok := m.Account.(*vless.MemoryAccount); !ok || account.Reverse != nil {
					return nil, nil
				}
			}
		default:
			return nil, nil
		}
	}
	native, err := newNativeInbound(h.construction, b)
	if err != nil {
		return nil, err
	}
	users, ok := native.(proxy.UserManager)
	if !ok || !slices.Equal(h.networks, native.Network()) {
		_ = common.Close(native)
		return nil, errors.New("replacement proxy changes native network or account management")
	}
	return &inboundGeneration{Inbound: native, UserManager: users}, nil
}

func receiverSettings(cfg *core.InboundHandlerConfig) (*proxyman.ReceiverConfig, error) {
	if cfg.ReceiverSettings == nil {
		return nil, fmt.Errorf("native inbound %q lacks receiver settings", cfg.Tag)
	}
	obj, err := cfg.ReceiverSettings.GetInstance()
	receiver, ok := obj.(*proxyman.ReceiverConfig)
	if !ok || err != nil {
		return nil, fmt.Errorf("native inbound %q has unsupported receiver settings", cfg.Tag)
	}
	return receiver, nil
}

func safeNewEndpoint(candidate *core.InboundHandlerConfig, active, desired []*core.InboundHandlerConfig) error {
	a, err := receiverSettings(candidate)
	if err != nil {
		return err
	}
	// Upstream gRPC binds asynchronously and reports startup errors only to
	// its log. A successful Start therefore cannot prove the endpoint is ready.
	if a.GetStreamSettings().GetProtocolName() == "grpc" {
		return fmt.Errorf("%w: native inbound %q cannot verify asynchronous listener startup", ErrReloadUnsupported, candidate.Tag)
	}
	for _, group := range [][]*core.InboundHandlerConfig{active, desired} {
		for _, other := range group {
			if other == candidate {
				continue
			}
			b, err := receiverSettings(other)
			if err != nil {
				return err
			}
			if endpointOverlap(a, b) {
				return fmt.Errorf("%w: native inbound %q overlaps listener %q and cannot be staged", ErrReloadUnsupported, candidate.Tag, other.Tag)
			}
		}
	}
	return nil
}

func endpointOverlap(a, b *proxyman.ReceiverConfig) bool {
	aa, ba := a.GetListen().AsAddress(), b.GetListen().AsAddress()
	if a.GetPortList() == nil || b.GetPortList() == nil {
		if a.GetPortList() != nil || b.GetPortList() != nil || aa == nil || ba == nil {
			return false
		}
		// Strip optional filesystem permissions and match padded/unpadded
		// abstract addresses conservatively.
		path := func(addr xnet.Address) string {
			s, _, _ := strings.Cut(addr.String(), ",")
			return strings.TrimLeft(s, "@")
		}
		return path(aa) == path(ba)
	}
	if aa != nil && ba != nil && aa.Family().IsIP() && ba.Family().IsIP() &&
		!aa.IP().IsUnspecified() && !ba.IP().IsUnspecified() && !aa.IP().Equal(ba.IP()) {
		return false
	}
	for _, ap := range a.GetPortList().GetRange() {
		for _, bp := range b.GetPortList().GetRange() {
			if ap.From <= bp.To && bp.From <= ap.To {
				return true
			}
		}
	}
	return false
}
