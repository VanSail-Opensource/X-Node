package xray

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// BuildCounts records actual native builder calls, excluding cheap comparison.
type BuildCounts struct{ Native, Inbounds, Outbounds, Routing int }

func sectionKey(v any) [32]byte { b, _ := json.Marshal(v); return sha256.Sum256(b) }

func staticKey(root map[string]any) [32]byte {
	copy := make(map[string]any, len(root))
	for k, v := range root {
		copy[k] = v
	}
	delete(copy, "inbounds")
	delete(copy, "outbounds")
	delete(copy, "routing")
	// Asset generation affects routing matchers, but only affects static core
	// components if one of them actually consumes geodata.
	if !assetReferences(copy, "env") {
		if env, ok := copy["env"].(map[string]any); ok {
			clean := make(map[string]any, len(env))
			for k, v := range env {
				if k != "XRAY_LOCATION_ASSET" {
					clean[k] = v
				}
			}
			copy["env"] = clean
		}
	}
	return sectionKey(copy)
}

func assetReferences(value any, exclude string) bool {
	switch v := value.(type) {
	case map[string]any:
		for k, x := range v {
			if k != exclude && assetReferences(x, "") {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if assetReferences(x, "") {
				return true
			}
		}
	case string:
		v = strings.TrimLeft(v, "!")
		return strings.HasPrefix(v, "geosite:") || strings.HasPrefix(v, "geoip:") ||
			strings.HasPrefix(v, "ext:") || strings.HasPrefix(v, "ext-ip:") ||
			strings.HasPrefix(v, "ext-domain:") || strings.HasPrefix(v, "ext-site:")
	}
	return false
}

func buildSections(p, previous *Prepared) error {
	raw, err := json.Marshal(p.Native)
	if err != nil {
		return err
	}
	env := preparedEnvironment(p)
	nativeEnvironmentMu.Lock()
	defer nativeEnvironmentMu.Unlock()
	restore, _, err := beginNativeRuntimeEnvironment(env)
	if err != nil {
		return err
	}
	defer restore()
	// Native addresses and port ranges can resolve env: during unmarshaling.
	var c conf.Config
	if err = json.Unmarshal(raw, &c); err != nil {
		return err
	}
	p.StaticHash = staticKey(p.Native)
	// API/metrics postprocessors inject additional handlers and routing. Keep
	// their complete upstream builder instead of bypassing those semantics.
	if previous == nil || nativeBuilderEnvironmentChanged(previous, env) || c.API != nil || c.Metrics != nil || len(c.Transport) > 0 {
		p.Core, err = c.Build()
		p.Counts = BuildCounts{1, len(c.InboundConfigs), len(c.OutboundConfigs), 1}
		if err == nil && c.API == nil && c.Metrics == nil && len(c.Transport) == 0 && c.RouterConfig != nil {
			p.ruleKeys = routingRuleKeys(c.RouterConfig.RuleList)
		}
		return err
	}
	if err = conf.PostProcessConfigureFile(&c); err != nil {
		return err
	}
	coreConfig := &core.Config{}
	if previous.StaticHash == p.StaticHash {
		for _, app := range previous.Core.App {
			if app.Type != routerMessageType {
				coreConfig.App = append(coreConfig.App, app)
			}
		}
	} else {
		base := c
		base.InboundConfigs, base.OutboundConfigs, base.RouterConfig = nil, nil, nil
		coreConfig, err = base.Build()
		p.Counts.Native++
		if err != nil {
			return err
		}
	}
	if e := buildRoutingSection(p, previous, coreConfig, c.RouterConfig); e != nil {
		return e
	}
	for i := range c.InboundConfigs {
		in := &c.InboundConfigs[i]
		if old := previous.Inbounds[in.Tag]; old != nil && previous.Keys["in:"+in.Tag] == p.Keys["in:"+in.Tag] {
			coreConfig.Inbound = append(coreConfig.Inbound, old)
			continue
		}
		built, e := in.Build()
		if e != nil {
			return fmt.Errorf("inbound %s: %w", in.Tag, e)
		}
		coreConfig.Inbound = append(coreConfig.Inbound, built)
		p.Counts.Inbounds++
	}
	for i := range c.OutboundConfigs {
		out := &c.OutboundConfigs[i]
		if old := previous.Outbounds[out.Tag]; old != nil && previous.Keys["out:"+out.Tag] == p.Keys["out:"+out.Tag] {
			coreConfig.Outbound = append(coreConfig.Outbound, old)
			continue
		}
		built, e := out.Build()
		if e != nil {
			return fmt.Errorf("outbound %s: %w", out.Tag, e)
		}
		coreConfig.Outbound = append(coreConfig.Outbound, built)
		p.Counts.Outbounds++
	}
	p.Core = coreConfig
	return nil
}

// Xray's native configuration builders read process-scoped asset paths.
// Do not leave values from validation or a failed candidate in the process.
var nativeEnvironmentMu sync.Mutex

func preparedEnvironment(p *Prepared) map[string]string {
	raw, _ := p.Native["env"].(map[string]any)
	env := make(map[string]string, len(raw))
	for k, v := range raw {
		if value, ok := v.(string); ok {
			env[k] = value
		}
	}
	return env
}
