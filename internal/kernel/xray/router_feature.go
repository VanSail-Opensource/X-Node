package xray

import (
	"context"
	"sync"
	"sync/atomic"

	approuter "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

// The dispatcher keeps a reference to its Router for the lifetime of the
// core. Replace the implementation behind that reference when strategy or
// script changes. Decisions already in progress finish on the old instance.
type reloadableRouter struct {
	mu         sync.RWMutex
	active     *routerGeneration
	ctx        context.Context
	dns        dns.Client
	outbounds  outbound.Manager
	dispatcher routing.Dispatcher
}

type routerGeneration struct {
	router approuter.Router
	refs   atomic.Int64
}

func (g *routerGeneration) release() {
	if g.refs.Add(-1) == 0 {
		_ = g.router.Close()
	}
}

func init() {
	common.Must(common.RegisterConfig((*RouterConfig)(nil), func(ctx context.Context, raw any) (any, error) {
		config := new(approuter.Config)
		if err := proto.Unmarshal(raw.(*RouterConfig).NativeValue, config); err != nil {
			return nil, err
		}
		r := &reloadableRouter{ctx: ctx}
		if err := core.RequireFeatures(ctx, func(d dns.Client, o outbound.Manager, dispatcher routing.Dispatcher) error {
			r.dns, r.outbounds, r.dispatcher = d, o, dispatcher
			g, err := r.build(config)
			if err == nil {
				r.active = g
			}
			return err
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}

func installReloadableRouter(config *core.Config) {
	for i, app := range config.App {
		if app.Type == routerMessageType {
			config.App[i] = serial.ToTypedMessage(&RouterConfig{NativeValue: app.Value})
		}
	}
}

func (r *reloadableRouter) build(config *approuter.Config) (*routerGeneration, error) {
	g := new(routerGeneration)
	if err := g.router.Init(r.ctx, config, r.dns, r.outbounds, r.dispatcher); err != nil {
		return nil, err
	}
	g.refs.Store(1) // owned by the candidate, then by the active pointer
	return g, nil
}

func (r *reloadableRouter) acquire() *routerGeneration {
	r.mu.RLock()
	g := r.active
	if g != nil {
		g.refs.Add(1)
	}
	r.mu.RUnlock()
	return g
}

func (r *reloadableRouter) publish(g *routerGeneration) {
	r.mu.Lock()
	old := r.active
	r.active = g
	r.mu.Unlock()
	if old != nil {
		old.release()
	}
}

func (*reloadableRouter) Type() any { return routing.RouterType() }

func (r *reloadableRouter) Start() error {
	g := r.acquire()
	if g == nil {
		return common.ErrNoClue
	}
	defer g.release()
	return g.router.Start()
}

func (r *reloadableRouter) Close() error {
	r.publish(nil)
	return nil
}

func (r *reloadableRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	g := r.acquire()
	if g == nil {
		return nil, common.ErrNoClue
	}
	defer g.release()
	return g.router.PickRoute(ctx)
}

func (r *reloadableRouter) AddRule(config *serial.TypedMessage, appendOnly bool) error {
	g := r.acquire()
	if g == nil {
		return common.ErrNoClue
	}
	defer g.release()
	return g.router.AddRule(config, appendOnly)
}

func (r *reloadableRouter) RemoveRule(tag string) error {
	g := r.acquire()
	if g == nil {
		return common.ErrNoClue
	}
	defer g.release()
	return g.router.RemoveRule(tag)
}

func (r *reloadableRouter) ListRule() []routing.Route {
	g := r.acquire()
	if g == nil {
		return nil
	}
	defer g.release()
	return g.router.ListRule()
}

func (r *reloadableRouter) GetPrincipleTarget(tag string) ([]string, error) {
	g := r.acquire()
	if g == nil {
		return nil, common.ErrNoClue
	}
	defer g.release()
	return g.router.GetPrincipleTarget(tag)
}

func (r *reloadableRouter) SetOverrideTarget(tag, target string) error {
	g := r.acquire()
	if g == nil {
		return common.ErrNoClue
	}
	defer g.release()
	return g.router.SetOverrideTarget(tag, target)
}

func (r *reloadableRouter) GetOverrideTarget(tag string) (string, error) {
	g := r.acquire()
	if g == nil {
		return "", common.ErrNoClue
	}
	defer g.release()
	return g.router.GetOverrideTarget(tag)
}
