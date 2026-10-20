package xray

import (
	"context"
	"errors"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

func hotEligible(old, next *Prepared) bool {
	if old.StaticHash != next.StaticHash || old.Router == nil || next.Router == nil {
		return false
	}
	if old.Router.DomainStrategy != next.Router.DomainStrategy || old.Router.Script != next.Router.Script {
		return false
	}
	if len(old.Core.Outbound) == 0 || len(next.Core.Outbound) == 0 || !proto.Equal(old.Core.Outbound[0], next.Core.Outbound[0]) {
		return false
	}
	if sameOutbounds(old, next) {
		return true
	}
	if old.Native["observatory"] != nil || old.Native["burstObservatory"] != nil {
		return false
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
		}
	}
	if len(old.Auxiliary) > 0 || len(next.Auxiliary) > 0 {
		for tag := range changed {
			if old.Outbounds[tag] != nil {
				return false
			}
		}
	}
	for _, p := range []*Prepared{old, next} {
		for _, raw := range p.Native["outbounds"].([]any) {
			out := raw.(map[string]any)
			tag, _ := out["tag"].(string)
			proxy, _ := out["proxySettings"].(map[string]any)
			peer, _ := proxy["tag"].(string)
			stream, _ := out["streamSettings"].(map[string]any)
			socket, _ := stream["sockopt"].(map[string]any)
			dialer, _ := socket["dialerProxy"].(string)
			if changed[tag] && unsafeOutbound(raw) || changed[peer] || changed[dialer] {
				return false
			}
		}
	}
	return true
}

func sameOutbounds(a, b *Prepared) bool {
	if len(a.Outbounds) != len(b.Outbounds) {
		return false
	}
	for tag, out := range a.Outbounds {
		if !proto.Equal(out, b.Outbounds[tag]) {
			return false
		}
	}
	return true
}

type outboundChange struct {
	tag       string
	old, next outbound.Handler
}

func (r *Runtime) updateLive(ctx context.Context, next *Prepared) (result error) {
	manager := r.instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	changes := []outboundChange{}
	committed := false
	defer func() {
		if !committed {
			for _, change := range changes {
				if change.next != nil {
					_ = common.Close(change.next)
				}
			}
		}
	}()
	for tag, cfg := range next.Outbounds {
		if proto.Equal(r.current.Outbounds[tag], cfg) {
			continue
		}
		object, err := core.CreateObject(r.instance, proto.Clone(cfg))
		if err != nil {
			return err
		}
		handler, ok := object.(outbound.Handler)
		if !ok {
			return errors.New("invalid outbound handler")
		}
		changes = append(changes, outboundChange{tag, manager.GetHandler(tag), handler})
	}
	for tag := range r.current.Outbounds {
		if next.Outbounds[tag] == nil {
			changes = append(changes, outboundChange{tag: tag, old: manager.GetHandler(tag)})
		}
	}
	tags := []string{}
	for _, change := range changes {
		if change.old != nil {
			tags = append(tags, change.tag)
		}
	}
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	release, err := r.registry.QuiesceOutbounds(child, tags)
	if err != nil {
		return err
	}
	defer release()
	installed := []outboundChange{}
	defer func() {
		if result == nil {
			return
		}
		// Only public manager interfaces are used. Restore handlers before rules;
		// the registry continues enforcing the latest authoritative credentials.
		for i := len(installed) - 1; i >= 0; i-- {
			change := installed[i]
			if change.next != nil {
				result = errors.Join(result, manager.RemoveHandler(ctx, change.tag))
			}
			if change.old != nil {
				result = errors.Join(result, manager.AddHandler(ctx, change.old))
			}
		}
		router := r.instance.GetFeature(routing.RouterType()).(routing.Router)
		result = errors.Join(result, router.AddRule(serial.ToTypedMessage(r.current.Router), false))
	}()
	for _, change := range changes {
		if change.next == nil {
			continue
		}
		if change.old != nil {
			if err = manager.RemoveHandler(ctx, change.tag); err != nil {
				return err
			}
		}
		installed = append(installed, change)
		if err = manager.AddHandler(ctx, change.next); err != nil {
			return err
		}
		r.stats.HandlerReplacements++
	}
	if !proto.Equal(r.current.Router, next.Router) {
		if err = r.replaceRouting(next); err != nil {
			return err
		}
	}
	r.registry.SetInboundEpochs(next.Epochs)
	if err = r.updateInbounds(ctx, next); err != nil {
		return err
	}
	for _, change := range changes {
		if change.next == nil {
			if err = manager.RemoveHandler(ctx, change.tag); err != nil {
				return err
			}
			installed = append(installed, change)
		}
	}
	for _, change := range changes {
		if change.old != nil {
			_ = common.Close(change.old)
		}
	}
	committed = true
	return nil
}
