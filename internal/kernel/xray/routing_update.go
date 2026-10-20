package xray

import (
	approuter "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

func (r *Runtime) replaceRouting(next *Prepared) error {
	config, appendOnly := next.Router, false
	old := r.current.Router
	if len(config.Rule) > len(old.Rule) && proto.Equal(withoutRules(old), withoutRules(config)) {
		appendOnly = true
		for i, rule := range old.Rule {
			if !proto.Equal(rule, config.Rule[i]) {
				appendOnly = false
				break
			}
		}
		if appendOnly {
			config = proto.Clone(config).(*approuter.Config)
			config.Rule = config.Rule[len(old.Rule):]
			config.BalancingRule = nil
		}
	}
	router := r.instance.GetFeature(routing.RouterType()).(routing.Router)
	if err := router.AddRule(serial.ToTypedMessage(config), appendOnly); err != nil {
		return err
	}
	r.stats.MatcherBuilds += uint64(len(config.Rule))
	return nil
}

func withoutRules(c *approuter.Config) *approuter.Config {
	copy := proto.Clone(c).(*approuter.Config)
	copy.Rule = nil
	return copy
}
