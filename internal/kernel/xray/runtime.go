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
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/protobuf/proto"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	wire "github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

// ErrReloadUnsupported means the requested transition cannot be applied
// without interrupting the serving Xray runtime.
var ErrReloadUnsupported = errors.New("configuration cannot be hot-reloaded")

type Runtime struct {
	observe  func(InboundObservation)
	mu       sync.Mutex
	instance *core.Instance
	current  *Prepared
	registry *sessions.Registry
	running  atomic.Bool
	bridge   *integration
	stats    Statistics
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
	r.running.Store(false)
	r.registry.CloseAll()
	if r.instance != nil {
		_ = r.instance.Close()
		r.instance = nil
	}
	r.current = nil
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
func (r *Runtime) ApplyPrepared(ctx context.Context, next *Prepared) (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recordBuilds(next)
	r.stats.ListenerGapMillis = 0
	r.stats.ListenerGapMicros = 0
	c := next.Source
	if r.instance != nil && !sameNonReloadableStatic(r.current, next) {
		return fmt.Errorf("%w: changed native startup-only settings", ErrReloadUnsupported)
	}
	nativeEnvironmentMu.Lock()
	defer nativeEnvironmentMu.Unlock()
	restore, err := setNativeEnvironment(preparedEnvironment(next))
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			restore()
		}
	}()
	if r.instance != nil {
		if err := r.applyLive(ctx, next); err != nil {
			return err
		}
		r.bridge.BanNanos.Store(int64(c.BanDuration()))
		r.current = next
		r.stats.LiveApplies++
		r.stats.LastMode = "live"
		return nil
	}
	if err := r.start(ctx, next, c); err != nil {
		return fmt.Errorf("Xray listener activation failed: %w", err)
	}
	r.stats.Rebuilds++
	r.stats.MatcherBuilds += uint64(len(next.Router.Rule))
	r.stats.LastMode = "start"
	return nil
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
	routes, err := r.prepareRoutingUpdate(next)
	if err != nil {
		return err
	}
	defer routes.abort()
	inbounds, err := r.prepareInboundUpdate(ctx, next)
	if err != nil {
		return err
	}
	defer inbounds.abort()

	if err = outbounds.publish(); err != nil {
		return err
	}
	if err = routes.commit(); err != nil {
		return err
	}
	features.Commit()
	inbounds.commit()
	outbounds.commit()
	r.stats.MatcherBuilds += uint64(routes.matchers)
	return nil
}

func (r *Runtime) start(ctx context.Context, p *Prepared, c wire.Config) error {
	bridge := &integration{Registry: r.registry, Observe: r.observe}
	bridge.setAuxiliary(p.Auxiliary)
	bridge.BanNanos.Store(int64(c.BanDuration()))
	child := context.WithValue(ctx, bridgeKey{}, bridge)
	// Native constructors may normalize protobufs. Preserve cached candidates.
	compiled := proto.Clone(p.Core).(*core.Config)
	installReloadableFeatures(compiled)
	installReloadableRouter(compiled)
	inst, err := core.NewWithContext(child, compiled)
	if err != nil {
		return err
	}
	if logger, ok := inst.GetFeature((*applog.Instance)(nil)).(xlog.Handler); ok {
		nlog.BindXray(logger)
	}
	r.registry.SetInboundEpochs(p.Epochs)
	if err = inst.Start(); err != nil {
		_ = inst.Close()
		return err
	}
	r.instance = inst
	r.bridge = bridge
	r.current = p
	r.running.Store(true)
	return nil
}
