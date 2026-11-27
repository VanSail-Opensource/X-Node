package xray

import (
	"slices"

	approuter "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

type routingUpdate struct {
	router     *reloadableRouter
	generation *routerGeneration
	append     *approuter.Config
	matchers   int
}

func (r *Runtime) prepareRoutingUpdate(next *Prepared) (*routingUpdate, error) {
	u := new(routingUpdate)
	if sameRouting(r.current, next) {
		return u, nil
	}
	u.router = r.instance.GetFeature(routing.RouterType()).(*reloadableRouter)
	config := next.Router
	old := r.current.Router
	if sameOutbounds(r.current, next) && len(config.Rule) > len(old.Rule) && r.current.Keys["routing-env"] == next.Keys["routing-env"] &&
		sameRouterSettings(old, config) && slices.EqualFunc(old.BalancingRule, config.BalancingRule, equalBalancingRule) &&
		slices.EqualFunc(old.Rule, config.Rule[:len(old.Rule)], equalRoutingRule) {
		// Keep existing matchers and balancer state for strict suffix appends.
		// With an outbound change, prepare the entire router before either
		// component is published so rule construction cannot fail mid-commit.
		u.append = &approuter.Config{Rule: config.Rule[len(old.Rule):]}
		u.matchers = len(u.append.Rule)
		return u, nil
	}
	generation, err := u.router.build(proto.Clone(config).(*approuter.Config))
	if err != nil {
		return nil, err
	}
	if err = generation.router.Start(); err != nil {
		generation.release()
		return nil, err
	}
	u.generation, u.matchers = generation, len(config.Rule)
	return u, nil
}

func (u *routingUpdate) abort() {
	if u.generation != nil {
		u.generation.release()
	}
}

func (u *routingUpdate) commit() error {
	switch {
	case u.append != nil:
		return u.router.AddRule(serial.ToTypedMessage(u.append), true)
	case u.generation != nil:
		u.router.publish(u.generation)
		u.generation = nil
	}
	return nil
}

func equalBalancingRule(a, b *approuter.BalancingRule) bool { return proto.Equal(a, b) }

func equalRoutingRule(a, b *approuter.RoutingRule) bool { return proto.Equal(a, b) }

func sameRouterSettings(a, b *approuter.Config) bool {
	return a.DomainStrategy == b.DomainStrategy && a.Script == b.Script
}

func sameRouting(a, b *Prepared) bool {
	return a.Keys["routing-env"] == b.Keys["routing-env"] && proto.Equal(a.Router, b.Router)
}
