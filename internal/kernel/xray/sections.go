package xray

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
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
		return strings.HasPrefix(v, "geosite:") || strings.HasPrefix(v, "geoip:")
	}
	return false
}

func buildSections(p, previous *Prepared) error {
	raw, err := json.Marshal(p.Native)
	if err != nil {
		return err
	}
	var c conf.Config
	if err = json.Unmarshal(raw, &c); err != nil {
		return err
	}
	for k, v := range c.Env {
		if err = os.Setenv(k, v); err != nil {
			return err
		}
	}
	p.StaticHash = staticKey(p.Native)
	// API/metrics postprocessors inject additional handlers and routing. Keep
	// their complete upstream builder instead of bypassing those semantics.
	if previous == nil || c.API != nil || c.Metrics != nil || len(c.Transport) > 0 {
		p.Core, err = c.Build()
		p.Counts = BuildCounts{1, len(c.InboundConfigs), len(c.OutboundConfigs), 1}
		return err
	}
	if err = conf.PostProcessConfigureFile(&c); err != nil {
		return err
	}
	coreConfig := &core.Config{}
	if previous.StaticHash == p.StaticHash {
		for _, app := range previous.Core.App {
			if app.Type != serial.ToTypedMessage(&router.Config{}).Type {
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
	if previous.Keys["routing"] == p.Keys["routing"] {
		coreConfig.App = append(coreConfig.App, serial.ToTypedMessage(previous.Router))
	} else {
		routing, e := c.RouterConfig.Build()
		if e != nil {
			return e
		}
		coreConfig.App = append(coreConfig.App, serial.ToTypedMessage(routing))
		p.Counts.Routing++
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
