package xray

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

var routerMessageType = serial.ToTypedMessage(&router.Config{}).Type

func routingRuleKeys(rules []json.RawMessage) [][32]byte {
	keys := make([][32]byte, len(rules))
	for i, rule := range rules {
		keys[i] = sha256.Sum256(rule)
	}
	return keys
}

func buildRoutingSection(p, previous *Prepared, coreConfig *core.Config, c *conf.RouterConfig) error {
	if previous.Router != nil && previous.ruleKeys != nil && previous.Keys["routing"] == p.Keys["routing"] {
		for _, app := range previous.Core.App {
			if app.Type == routerMessageType {
				p.Router, p.ruleKeys = previous.Router, previous.ruleKeys
				coreConfig.App = append(coreConfig.App, app)
				return nil
			}
		}
	}
	var err error
	if c.Script != "" {
		// Let upstream check the interaction between scripts and field rules.
		p.Router, err = c.Build()
	} else {
		p.Router, p.ruleKeys, err = compileRoutingRules(c, previous)
	}
	if err != nil {
		return err
	}
	coreConfig.App = append(coreConfig.App, serial.ToTypedMessage(p.Router))
	p.Counts.Routing++
	return nil
}

func compileRoutingRules(c *conf.RouterConfig, previous *Prepared) (*router.Config, [][32]byte, error) {
	header := *c
	header.RuleList = nil
	compiled, err := header.Build()
	if err != nil {
		return nil, nil, err
	}
	// Native rule protobufs store asset references, not loaded matcher data.
	// Matchers still resolve the current asset generation at publication.
	old := make(map[[32]byte]*router.RoutingRule, len(previous.ruleKeys))
	if previous.Router != nil && len(previous.ruleKeys) == len(previous.Router.Rule) {
		for i, key := range previous.ruleKeys {
			old[key] = previous.Router.Rule[i]
		}
	}
	keys := routingRuleKeys(c.RuleList)
	compiled.Rule = make([]*router.RoutingRule, 0, len(keys))
	for i, key := range keys {
		rule := old[key]
		if rule == nil {
			one, err := (&conf.RouterConfig{RuleList: c.RuleList[i : i+1]}).Build()
			if err != nil {
				return nil, nil, err
			}
			rule = one.Rule[0]
			if err := validateRuleAttributes(rule); err != nil {
				return nil, nil, err
			}
		}
		compiled.Rule = append(compiled.Rule, rule)
	}
	return compiled, keys, nil
}

func validateRouteAttributes(config *router.Config) error {
	if config == nil {
		return nil
	}
	for _, rule := range config.Rule {
		if err := validateRuleAttributes(rule); err != nil {
			return err
		}
	}
	return nil
}

func validateRuleAttributes(rule *router.RoutingRule) error {
	for _, expression := range rule.Attributes {
		if _, err := regexp.Compile(expression); err != nil {
			return errors.New("invalid routing attribute expression")
		}
	}
	return nil
}
