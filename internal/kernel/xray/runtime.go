package xray

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	applog "github.com/xtls/xray-core/app/log"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/protobuf/proto"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	wire "github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

// ErrReloadUnsupported asks the activation path to use a cold Xray cutover
// instead of trying to publish the transition in the serving core.
var ErrReloadUnsupported = errors.New("configuration cannot be hot-reloaded")

type Runtime struct {
	observe        func(InboundObservation)
	mu             sync.Mutex
	instance       *core.Instance
	instanceCancel context.CancelFunc
	current        *Prepared
	registry       *sessions.Registry
	running        atomic.Bool
	bridge         *integration
	stats          Statistics
	failedColdKey  [32]byte
}

func New(registry *sessions.Registry) *Runtime { return &Runtime{registry: registry} }
func (r *Runtime) Ready() bool {
	// Readiness must never wait behind preparation, quiescence or listeners;
	// the actor needs to keep acknowledging traffic during those operations.
	return r.running.Load()
}
func (r *Runtime) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopInstance()
	r.failedColdKey = [32]byte{}
}

func (r *Runtime) stopInstance() {
	r.running.Store(false)
	if r.bridge != nil {
		r.bridge.stopping.Store(true)
	}
	if r.instanceCancel != nil {
		r.instanceCancel()
		r.instanceCancel = nil
	}
	r.registry.CloseAll()
	if r.instance != nil {
		_ = r.instance.Close()
		r.instance = nil
	}
	r.current = nil
	r.bridge = nil
}
func (r *Runtime) Apply(ctx context.Context, c wire.Config) error {
	next, err := r.Prepare(c)
	if err != nil {
		return err
	}
	return r.ApplyPrepared(ctx, next)
}

// Prepare builds against one immutable active snapshot, without opening sockets.
func (r *Runtime) Prepare(c wire.Config) (*Prepared, error) {
	r.mu.Lock()
	previous := r.current
	r.mu.Unlock()
	return PrepareCached(c, previous)
}

// ApplyPrepared consumes a validated candidate without parsing/building twice.
// ctx is the runtime lifetime, not the supersedable preparation context.
func (r *Runtime) ApplyPrepared(ctx context.Context, next *Prepared) error {
	return r.ApplyPreparedContext(ctx, ctx, next, true)
}

// ApplyPreparedContext keeps the running instance on the lifetime context.
// A superseded request can abandon preparation, but cannot abandon recovery
// after a cold cutover starts. Retry permits an explicit repeat of a
// configuration that previously failed after taking the core offline.
func (r *Runtime) ApplyPreparedContext(ctx, operation context.Context, next *Prepared, retry bool) (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := operation.Err(); err != nil {
		return err
	}
	r.recordBuilds(next)
	r.stats.ListenerGapMillis = 0
	r.stats.ListenerGapMicros = 0
	nativeEnvironmentMu.Lock()
	defer nativeEnvironmentMu.Unlock()
	restore, commit, err := beginNativeRuntimeEnvironment(preparedEnvironment(next))
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			restore()
		} else {
			commit()
		}
	}()
	if r.instance != nil {
		if receiverChanged(r.current, next) {
			return r.reloadCold(ctx, operation, next, retry, restore, "receiver")
		}
		if !sameNonReloadableStatic(r.current, next) {
			return r.reloadCold(ctx, operation, next, retry, restore, "cold")
		}
		if err := r.applyLive(ctx, next); err != nil {
			if errors.Is(err, ErrReloadUnsupported) {
				return r.reloadCold(ctx, operation, next, retry, restore, "cold")
			}
			return err
		}
		r.bridge.BanNanos.Store(int64(next.Source.BanDuration()))
		r.current = next
		r.stats.LiveApplies++
		r.stats.LastMode = "live"
		return nil
	}
	compiled, err := compiledRuntime(next)
	if err != nil {
		return err
	}
	if err := r.startCompiled(ctx, next, compiled); err != nil {
		return fmt.Errorf("Xray listener activation failed: %w", err)
	}
	r.recordStart(next, "start")
	r.failedColdKey = [32]byte{}
	return nil
}

func (r *Runtime) recordStart(p *Prepared, mode string) {
	r.stats.Rebuilds++
	r.stats.MatcherBuilds += uint64(len(p.Router.Rule))
	r.stats.LastMode = mode
}

func (r *Runtime) applyLive(ctx context.Context, next *Prepared) error {
	if blocker := outboundReloadBlocker(r.current, next); blocker != "" {
		return fmt.Errorf("%w: %s", ErrReloadUnsupported, blocker)
	}
	features, err := prepareFeatureReload(r.instance, r.current, next)
	if err != nil {
		return err
	}
	defer features.Discard()
	outbounds, err := r.prepareOutboundUpdate(next)
	if err != nil {
		return err
	}
	defer outbounds.abort()
	routes, err := r.prepareRoutingUpdate(next, true)
	if err != nil {
		return err
	}
	defer routes.abort()
	inbounds, err := r.prepareInboundUpdate(ctx, next)
	if err != nil {
		return err
	}
	defer inbounds.abort()

	if err = r.publishRouting(outbounds, routes); err != nil {
		return err
	}
	features.Commit()
	inbounds.commit()
	outbounds.commit()
	r.stats.MatcherBuilds += uint64(routes.matchers)
	return nil
}

func (r *Runtime) publishRouting(outbounds *outboundUpdate, routes *routingUpdate) error {
	if outbounds != nil {
		if routes.append != nil {
			return errors.New("route append cannot replace outbound handlers")
		}
		router := r.instance.GetFeature(routing.RouterType()).(*reloadableRouter)
		// Lock the manager first. A native API change can hold that lock
		// while starting a handler, whose startup may resolve a route.
		outbounds.manager.mu.Lock()
		router.mu.Lock()
		err := outbounds.publishLocked()
		var old *routerGeneration
		if err == nil && routes.generation != nil {
			old = router.swapLocked(routes.generation)
			routes.generation = nil
		}
		router.mu.Unlock()
		outbounds.manager.mu.Unlock()
		if old != nil {
			old.release()
		}
		return err
	}
	old, err := routes.commit()
	if old != nil {
		old.release()
	}
	return err
}

func compiledRuntime(p *Prepared) (*core.Config, error) {
	// Native constructors may normalize protobufs. Preserve cached candidates.
	compiled := proto.Clone(p.Core).(*core.Config)
	installReloadableFeatures(compiled)
	installReloadableRouter(compiled)
	installRouteDispatcher(compiled)
	for _, cfg := range compiled.Inbound {
		if err := enableSynchronousGRPC(cfg); err != nil {
			return nil, err
		}
	}
	return compiled, nil
}

func (r *Runtime) startCompiled(ctx context.Context, p *Prepared, compiled *core.Config) error {
	bridge := &integration{Registry: r.registry, Observe: r.observe}
	bridge.setAuxiliary(p.Auxiliary)
	bridge.BanNanos.Store(int64(p.Source.BanDuration()))
	child, cancel := context.WithCancel(context.WithValue(ctx, bridgeKey{}, bridge))
	inst, err := core.NewWithContext(child, compiled)
	if err != nil {
		cancel()
		return err
	}
	if logger, ok := inst.GetFeature((*applog.Instance)(nil)).(xlog.Handler); ok {
		nlog.BindXray(logger)
	}
	r.registry.SetInboundEpochs(p.Epochs)
	if err = inst.Start(); err != nil {
		cancel()
		_ = inst.Close()
		return err
	}
	r.instance = inst
	r.instanceCancel = cancel
	r.bridge = bridge
	r.current = p
	r.running.Store(true)
	return nil
}
