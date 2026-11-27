package xray

import (
	"slices"

	approuter "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

func (r *Runtime) replaceRouting(next *Prepared) error {
	config, appendOnly := next.Router, false
	old := r.current.Router
	if len(config.Rule) > len(old.Rule) && r.current.Keys["routing-env"] == next.Keys["routing-env"] &&
		sameRouterSettings(old, config) && slices.EqualFunc(old.BalancingRule, config.BalancingRule, equalBalancingRule) {
		appendOnly = true
		for i, rule := range old.Rule {
			if !proto.Equal(rule, config.Rule[i]) {
				appendOnly = false
				break
			}
		}
		if appendOnly {
			config = &approuter.Config{Rule: config.Rule[len(old.Rule):]}
		}
	}
	router := r.instance.GetFeature(routing.RouterType()).(routing.Router)
	if err := router.AddRule(serial.ToTypedMessage(config), appendOnly); err != nil {
		return err
	}
	r.stats.MatcherBuilds += uint64(len(config.Rule))
	return nil
}

func equalBalancingRule(a, b *approuter.BalancingRule) bool {
	return proto.Equal(a, b)
}

func sameRouterSettings(a, b *approuter.Config) bool {
	return a.DomainStrategy == b.DomainStrategy && a.Script == b.Script
}

func sameRouting(a, b *Prepared) bool {
	return a.Keys["routing-env"] == b.Keys["routing-env"] && proto.Equal(a.Router, b.Router)
}

// Routing edits can also introduce or remove a dedicated outbound. Native
// listener and static core changes are distinct, broader configuration changes.
func routingEdit(old, next *Prepared) bool {
	if old == nil || old.Router == nil || next.Router == nil || old.StaticHash != next.StaticHash || sameRouting(old, next) ||
		len(old.Inbounds) != len(next.Inbounds) {
		return false
	}
	for tag, config := range old.Inbounds {
		if !proto.Equal(config, next.Inbounds[tag]) || old.Epochs[tag] != next.Epochs[tag] || old.Auxiliary[tag] != next.Auxiliary[tag] {
			return false
		}
	}
	return true
}
