package xray

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	applog "github.com/xtls/xray-core/app/log"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

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
}

func New(registry *sessions.Registry) *Runtime { return &Runtime{registry: registry} }
func (r *Runtime) Ready() bool {
	if !r.running.Load() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.instance != nil && r.instance.IsRunning()
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
	next, err := Prepare(c)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry.SetInboundEpochs(next.Epochs)
	if r.instance != nil && r.current.BaseHash == next.BaseHash && (len(reload) == 0 || !reload[0]) {
		if r.bridge != nil {
			r.bridge.BanNanos.Store(int64(c.BanDuration()))
			r.bridge.setAuxiliary(next.Auxiliary)
		}
		err = r.updateInbounds(ctx, next)
		if err == nil {
			r.current = next
			r.running.Store(true)
			return nil
		}
		// Rebuild from the desired authorization. Never reinstall a revoked account during rollback.
	}
	old := r.current
	r.running.Store(false)
	r.registry.CloseAll()
	if r.instance != nil {
		_ = r.instance.Close()
		r.instance = nil
	}
	if err = r.start(ctx, next, c); err != nil {
		if old != nil {
			safe := wire.Clone(old.Source)
			safe.Users = compatibleUsers(c.Users, old.Inbounds)
			if rollback, e := Prepare(safe); e == nil {
				_ = r.start(ctx, rollback, safe)
			}
		}
		return errors.New("Xray listener activation failed")
	}
	return nil
}
func (r *Runtime) start(ctx context.Context, p *Prepared, c wire.Config) error {
	r.registry.SetInboundEpochs(p.Epochs)
	bridge := &integration{Registry: r.registry, Observe: r.observe}
	bridge.setAuxiliary(p.Auxiliary)
	bridge.BanNanos.Store(int64(c.BanDuration()))
	child := context.WithValue(ctx, bridgeKey{}, bridge)
	inst, err := core.NewWithContext(child, p.Core)
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
func (r *Runtime) updateInbounds(ctx context.Context, next *Prepared) error {
	manager := r.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	for tag := range r.current.Inbounds {
		if _, ok := next.Inbounds[tag]; !ok {
			if err := manager.RemoveHandler(ctx, tag); err != nil {
				return err
			}
		}
	}
	for tag, cfg := range next.Inbounds {
		old, exists := r.current.Inbounds[tag]
		if exists && proto.Equal(old, cfg) {
			continue
		}
		if exists && r.current.InboundBase[tag] == next.InboundBase[tag] && proto.Equal(old.ReceiverSettings, cfg.ReceiverSettings) {
			handler, err := manager.GetHandler(ctx, tag)
			if err == nil {
				if getter, ok := handler.(proxy.GetInbound); ok {
					if users, ok := getter.GetInbound().(proxy.UserManager); ok {
						accounts, err := memoryUsers(cfg)
						if err != nil {
							return err
						}
						desired := map[string]*protocol.MemoryUser{}
						for _, u := range accounts {
							desired[u.Email] = u
						}
						for _, u := range users.GetUsers(ctx) {
							n, ok := desired[u.Email]
							if !ok || !u.Account.Equals(n.Account) {
								if err := users.RemoveUser(ctx, u.Email); err != nil {
									return err
								}
							}
						}
						for _, u := range accounts {
							existing := users.GetUser(ctx, u.Email)
							if existing == nil {
								if err := users.AddUser(ctx, u); err != nil {
									return err
								}
							}
						}
						continue
					}
				}
			}
		}
		if exists {
			r.registry.CloseUserInbound(tag)
			if err := manager.RemoveHandler(ctx, tag); err != nil {
				return err
			}
		}
		if err := core.AddInboundHandler(r.instance, cfg); err != nil {
			return err
		}
	}
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
func memoryUsers(cfg *core.InboundHandlerConfig) ([]*protocol.MemoryUser, error) {
	msg, err := cfg.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	if wrapped, ok := msg.(*InboundConfig); ok {
		msg, err = wrapped.native().GetInstance()
		if err != nil {
			return nil, err
		}
	}
	var out []*protocol.MemoryUser
	var failure error
	var walk func(protoreflect.Message)
	walk = func(m protoreflect.Message) {
		if u, ok := m.Interface().(*protocol.User); ok {
			memory, err := u.ToMemoryUser()
			if err != nil {
				failure = err
			} else {
				out = append(out, memory)
			}
			return
		}
		m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			if f.IsList() && f.Kind() == protoreflect.MessageKind {
				list := v.List()
				for i := 0; i < list.Len(); i++ {
					walk(list.Get(i).Message())
				}
			} else if !f.IsMap() && f.Kind() == protoreflect.MessageKind {
				walk(v.Message())
			}
			return true
		})
	}
	walk(msg.ProtoReflect())
	if failure != nil {
		return nil, fmt.Errorf("invalid memory account")
	}
	return out, nil
}
