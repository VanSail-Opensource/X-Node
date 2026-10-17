package xray

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
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
			return nil, errors.New("native object is not an inbound")
		}
		users, ok := object.(proxy.UserManager)
		if !ok {
			return nil, errors.New("managed inbound lacks public user management")
		}
		bridge, _ := ctx.Value(bridgeKey{}).(*integration)
		return &observedInbound{Inbound: inbound, UserManager: users, bridge: bridge, tag: config.Tag, reality: config.Reality}, nil
	}))
}

type observedInbound struct {
	proxy.Inbound
	proxy.UserManager
	bridge  *integration
	tag     string
	reality bool
}

func (h *observedInbound) Close() error { return common.Close(h.Inbound) }
func (h *observedInbound) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if h.reality || h.bridge == nil || h.bridge.Observe == nil {
		return h.Inbound.Process(ctx, network, conn, dispatcher)
	}
	tracker := &authDispatcher{Dispatcher: dispatcher}
	err := h.Inbound.Process(ctx, network, conn, tracker)
	if tracker.authorized.Load() || ctx.Err() != nil {
		return err
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil && strings.HasPrefix(inbound.User.Email, "user@") {
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
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil && strings.HasPrefix(inbound.User.Email, "user@") {
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
