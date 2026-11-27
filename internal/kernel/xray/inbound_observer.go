package xray

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type InboundObservation struct {
	IP         netip.Addr
	Rule       string
	InboundTag string
}

func init() {
	common.Must(common.RegisterConfig((*InboundConfig)(nil), func(ctx context.Context, raw any) (any, error) {
		config := raw.(*InboundConfig)
		inbound, err := newNativeInbound(ctx, config)
		if err != nil {
			return nil, err
		}
		bridge, _ := ctx.Value(bridgeKey{}).(*integration)
		var gate *inboundGate
		if bridge != nil {
			if pending := bridge.inboundGate.Load(); pending != nil && pending.tag == config.Tag {
				gate = pending
			}
		}
		if gate != nil && gate.auxiliary {
			return &gatedInbound{Inbound: inbound, gate: gate}, nil
		}
		users, ok := inbound.(proxy.UserManager)
		if !ok {
			_ = common.Close(inbound)
			return nil, errors.New("managed inbound lacks public user management")
		}
		return &observedInbound{
			active:   &inboundGeneration{Inbound: inbound, UserManager: users},
			networks: inbound.Network(), construction: ctx,
			bridge: bridge, gate: gate, tag: config.Tag, reality: config.Reality,
		}, nil
	}))
}

func newNativeInbound(ctx context.Context, config *InboundConfig) (proxy.Inbound, error) {
	message, err := config.native().GetInstance()
	if err != nil {
		return nil, err
	}
	object, err := common.CreateObject(ctx, message)
	if err != nil {
		return nil, err
	}
	inbound, ok := object.(proxy.Inbound)
	if !ok {
		_ = common.Close(object)
		return nil, errors.New("native object is not an inbound")
	}
	return inbound, nil
}

type inboundGeneration struct {
	proxy.Inbound
	proxy.UserManager
	activeCalls int // guarded by the parent
}

type observedInbound struct {
	mu           sync.Mutex
	active       *inboundGeneration
	networks     []xnet.Network
	construction context.Context
	bridge       *integration
	gate         *inboundGate
	tag          string
	reality      bool
}

func (h *observedInbound) acquire() *inboundGeneration {
	h.mu.Lock()
	defer h.mu.Unlock()
	generation := h.active
	if generation != nil {
		generation.activeCalls++
	}
	return generation
}

func (h *observedInbound) release(generation *inboundGeneration) {
	h.mu.Lock()
	generation.activeCalls--
	retired := generation != h.active && generation.activeCalls == 0
	h.mu.Unlock()
	if retired {
		_ = common.Close(generation.Inbound)
	}
}

func (h *observedInbound) replace(next *inboundGeneration) error {
	h.mu.Lock()
	old := h.active
	h.active = next
	retired := old != nil && old.activeCalls == 0
	h.mu.Unlock()
	if retired {
		return common.Close(old.Inbound)
	}
	return nil
}

func (h *observedInbound) Close() error            { return h.replace(nil) }
func (h *observedInbound) Network() []xnet.Network { return h.networks }
func (h *observedInbound) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	g := h.acquire()
	if g == nil {
		return net.ErrClosed
	}
	defer h.release(g)
	return g.AddUser(ctx, user)
}
func (h *observedInbound) RemoveUser(ctx context.Context, email string) error {
	g := h.acquire()
	if g == nil {
		return net.ErrClosed
	}
	defer h.release(g)
	return g.RemoveUser(ctx, email)
}
func (h *observedInbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	g := h.acquire()
	if g == nil {
		return nil
	}
	defer h.release(g)
	return g.GetUser(ctx, email)
}
func (h *observedInbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	g := h.acquire()
	if g == nil {
		return nil
	}
	defer h.release(g)
	return g.GetUsers(ctx)
}
func (h *observedInbound) GetUsersCount(ctx context.Context) int64 {
	g := h.acquire()
	if g == nil {
		return 0
	}
	defer h.release(g)
	return g.GetUsersCount(ctx)
}

func (h *observedInbound) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if h.gate != nil && !h.gate.await(ctx) {
		return net.ErrClosed
	}
	generation := h.acquire()
	if generation == nil {
		return net.ErrClosed
	}
	defer h.release(generation)
	if h.bridge == nil || h.bridge.Observe == nil {
		return generation.Process(ctx, network, conn, dispatcher)
	}
	tracker := &authDispatcher{Dispatcher: dispatcher}
	err := generation.Process(ctx, network, conn, tracker)
	if tracker.authorized.Load() || ctx.Err() != nil {
		return err
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		return err
	}
	addr, parseErr := netip.ParseAddrPort(conn.RemoteAddr().String())
	if parseErr != nil {
		return err
	}
	rule := "xray_invalid"
	if network == xnet.Network_TCP && (err == nil || strings.Contains(strings.ToLower(err.Error()), "eof") || strings.Contains(strings.ToLower(err.Error()), "timeout")) {
		rule = "xray_tcp_probe"
	}
	if err != nil {
		text := strings.ToLower(err.Error())
		if strings.Contains(text, "invalid user") || strings.Contains(text, "invalid request user id") || strings.Contains(text, "unknown user") || strings.Contains(text, "invalid account") || strings.Contains(text, "authentication") || strings.Contains(text, "invalid password") {
			rule = "xray_auth_failure"
		}
	}
	h.bridge.Observe(InboundObservation{IP: addr.Addr().Unmap(), Rule: rule, InboundTag: h.tag})
	return err
}

type authDispatcher struct {
	routing.Dispatcher
	authorized atomic.Bool
}

func (d *authDispatcher) mark(ctx context.Context) {
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		d.authorized.Store(true)
	}
}
func (d *authDispatcher) Dispatch(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
	d.mark(ctx)
	return d.Dispatcher.Dispatch(ctx, destination)
}
func (d *authDispatcher) DispatchLink(ctx context.Context, destination xnet.Destination, link *transport.Link) error {
	d.mark(ctx)
	return d.Dispatcher.DispatchLink(ctx, destination, link)
}

func (r *Runtime) SetInboundObserver(observe func(InboundObservation)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observe = observe
}
