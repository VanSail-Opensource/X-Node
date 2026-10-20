package xray

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/protobuf/proto"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	wire "github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

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
func (r *Runtime) Apply(ctx context.Context, c wire.Config, reload ...bool) error {
	next, err := r.Prepare(c)
	if err != nil {
		return err
	}
	return r.ApplyPrepared(ctx, next, len(reload) > 0 && reload[0])
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
func (r *Runtime) ApplyPrepared(ctx context.Context, next *Prepared, force bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recordBuilds(next)
	r.stats.ListenerGapMillis = 0
	c := next.Source
	if r.instance != nil && !force && hotEligible(r.current, next) {
		if r.bridge != nil {
			r.bridge.BanNanos.Store(int64(c.BanDuration()))
			r.bridge.setAuxiliary(next.Auxiliary)
		}
		if err := r.updateLive(ctx, next); err == nil {
			r.current = next
			r.running.Store(true)
			r.stats.LiveApplies++
			r.stats.LastMode = "live"
			return nil
		} else {
			r.bridge.setAuxiliary(r.current.Auxiliary)
			// Reconcile listeners from the last working structure with current
			// authorization. A rejected hot update must not restart other users.
			old := r.current
			safe := wire.Clone(old.Source)
			safe.Users = compatibleUsers(c.Users, old.Inbounds)
			if rollback, e := PrepareCached(safe, old); e == nil {
				r.current = next
				r.registry.SetInboundEpochs(rollback.Epochs)
				if e = r.updateInbounds(ctx, rollback); e == nil {
					r.current = rollback
					return err
				}
				r.current = old
			}
			return err
		}
	}
	old := r.current
	started := time.Now()
	r.running.Store(false)
	r.registry.CloseAll()
	if r.instance != nil {
		_ = r.instance.Close()
		r.instance = nil
	}
	if err := r.start(ctx, next, c); err != nil {
		if old != nil {
			safe := wire.Clone(old.Source)
			safe.Users = compatibleUsers(c.Users, old.Inbounds)
			if rollback, e := PrepareCached(safe, old); e == nil {
				_ = r.start(ctx, rollback, safe)
			}
		}
		return errors.New("Xray listener activation failed")
	}
	r.stats.Rebuilds++
	r.stats.MatcherBuilds += uint64(len(next.Router.Rule))
	r.stats.LastMode = "rebuild"
	r.stats.ListenerGapMillis = time.Since(started).Milliseconds()
	return nil
}
func (r *Runtime) start(ctx context.Context, p *Prepared, c wire.Config) error {
	r.registry.SetInboundEpochs(p.Epochs)
	bridge := &integration{Registry: r.registry, Observe: r.observe}
	bridge.setAuxiliary(p.Auxiliary)
	bridge.BanNanos.Store(int64(c.BanDuration()))
	child := context.WithValue(ctx, bridgeKey{}, bridge)
	// Native constructors may normalize protobufs. Preserve cached candidates.
	inst, err := core.NewWithContext(child, proto.Clone(p.Core).(*core.Config))
	if err != nil {
		return err
	}
	if logger, ok := inst.GetFeature((*applog.Instance)(nil)).(xlog.Handler); ok {
		nlog.BindXray(logger)
	}
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
func compatibleUsers(users []wire.User, inbounds map[string]*core.InboundHandlerConfig) []wire.User {
	out := []wire.User{}
	for _, u := range wire.Clone(users) {
		tags := []string{}
		for _, tag := range u.InboundTags {
			if _, ok := inbounds[tag]; ok {
				tags = append(tags, tag)
			} else {
				delete(u.Credentials, tag)
			}
		}
		u.InboundTags = tags
		transit := u.TransitCredentials[:0]
		for _, binding := range u.TransitCredentials {
			if _, exists := inbounds[binding.InboundTag]; exists {
				transit = append(transit, binding)
			}
		}
		u.TransitCredentials = transit
		if len(tags) > 0 {
			out = append(out, u)
		}
	}
	return out
}
