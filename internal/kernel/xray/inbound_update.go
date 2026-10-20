package xray

import (
	"context"
	"fmt"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy"
	"google.golang.org/protobuf/proto"
)

func (r *Runtime) updateInbounds(ctx context.Context, next *Prepared) error {
	manager := r.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	for tag := range r.current.Inbounds {
		if _, ok := next.Inbounds[tag]; !ok {
			if _, err := manager.GetHandler(ctx, tag); err != nil {
				continue
			}
			if err := manager.RemoveHandler(ctx, tag); err != nil {
				return err
			}
		}
	}
	for tag, cfg := range next.Inbounds {
		old, exists := r.current.Inbounds[tag]
		_, lookupErr := manager.GetHandler(ctx, tag)
		if exists && lookupErr == nil && proto.Equal(old, cfg) {
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
		if exists && lookupErr == nil {
			r.registry.CloseUserInbound(tag)
			if err := manager.RemoveHandler(ctx, tag); err != nil {
				return err
			}
		}
		object, err := core.CreateObject(r.instance, cfg)
		if err != nil {
			return err
		}
		handler, ok := object.(inbound.Handler)
		if !ok {
			return fmt.Errorf("invalid inbound handler")
		}
		if err = manager.AddHandler(ctx, handler); err != nil {
			_ = common.Close(handler)
			return err
		}
		r.stats.HandlerReplacements++
	}
	return nil
}
