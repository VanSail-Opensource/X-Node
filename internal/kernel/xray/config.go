package xray

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

type Prepared struct {
	Source      protocol.Config
	Native      map[string]any
	Core        *core.Config
	Inbounds    map[string]*core.InboundHandlerConfig
	BaseHash    [32]byte
	InboundBase map[string]string
	Epochs      map[string]string
	Auxiliary   map[string]bool
	Outbounds   map[string]*core.OutboundHandlerConfig
	Router      *router.Config
	StaticHash  [32]byte
	Keys        map[string][32]byte
	Counts      BuildCounts
}

func Prepare(c protocol.Config) (*Prepared, error) {
	return PrepareCached(c, nil)
}

// PrepareCached reuses immutable sections of one previous candidate. The
// caller owns serialization; neither source nor previous protobufs are mutated.
func PrepareCached(c protocol.Config, previous *Prepared) (*Prepared, error) {
	if err := protocol.ValidateNativePolicies(c); err != nil {
		return nil, err
	}
	tags, err := protocol.AuxiliaryInboundTags(c.Xray)
	if err != nil {
		return nil, err
	}
	auxiliary := map[string]bool{}
	for _, tag := range tags {
		auxiliary[tag] = true
	}
	for _, user := range c.Users {
		for _, tag := range user.InboundTags {
			if auxiliary[tag] {
				return nil, errors.New("managed users cannot bind auxiliary listeners")
			}
		}
	}
	var root map[string]any
	if err := json.Unmarshal(c.Xray, &root); err != nil || root == nil {
		return nil, errors.New("invalid native configuration")
	}
	supported := map[string]bool{}
	typ := reflect.TypeOf(conf.Config{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag != "" {
			supported[tag] = true
		}
	}
	for key := range root {
		if !supported[key] {
			return nil, fmt.Errorf("unsupported Xray root field %s", key)
		}
	}
	// Assets are prepared, hash checked and scheduled by the agent; do not run a second unverified core downloader.
	delete(root, "geodata")
	base, epochs, err := renderInbounds(c, root, auxiliary)
	if err != nil {
		return nil, err
	}
	inbounds := root["inbounds"].([]any)
	if err := renderGlobals(c, root); err != nil {
		return nil, err
	}
	p := &Prepared{Source: protocol.Clone(c), Native: root, InboundBase: base, Epochs: epochs, Auxiliary: auxiliary, Keys: map[string][32]byte{}}
	for _, raw := range inbounds {
		in := raw.(map[string]any)
		tag := in["tag"].(string)
		p.Keys["in:"+tag] = sectionKey([]any{raw, base[tag]})
	}
	for _, raw := range root["outbounds"].([]any) {
		out := raw.(map[string]any)
		material, err := listenerIdentity(raw)
		if err != nil {
			return nil, err
		}
		p.Keys["out:"+out["tag"].(string)] = sectionKey(material)
	}
	routingKey := []any{root["routing"]}
	if assetReferences(root["routing"], "") {
		routingKey = append(routingKey, root["env"])
	}
	p.Keys["routing"] = sectionKey(routingKey)
	if err := buildSections(p, previous); err != nil {
		return nil, fmt.Errorf("Xray configuration validation failed: %w", err)
	}
	pb := p.Core
	// Loading PEM during configuration parsing does not itself check key pairing.
	for _, in := range pb.Inbound {
		if e := validateTLSMaterial(in.ReceiverSettings); e != nil {
			return nil, e
		}
	}
	for i, app := range pb.App {
		obj, err := app.GetInstance()
		if err != nil {
			return nil, err
		}
		if _, ok := obj.(*proxyman.OutboundConfig); ok {
			pb.App[i] = serial.ToTypedMessage(&ManagerConfig{})
		}
		if routing, ok := obj.(*router.Config); ok {
			p.Router = routing
		}
	}
	pbmap := map[string]*core.InboundHandlerConfig{}
	for _, in := range pb.Inbound {
		obj, err := in.ProxySettings.GetInstance()
		if err != nil {
			return nil, err
		}
		_, wrapped := obj.(*InboundConfig)
		if !auxiliary[in.Tag] && !wrapped {
			reality := false
			for _, raw := range inbounds {
				item, _ := raw.(map[string]any)
				if item["tag"] == in.Tag {
					stream, _ := item["streamSettings"].(map[string]any)
					reality = stream["security"] == "reality"
					break
				}
			}
			in.ProxySettings = serial.ToTypedMessage(&InboundConfig{NativeType: in.ProxySettings.Type, NativeValue: in.ProxySettings.Value, Tag: in.Tag, Reality: reality})
		}
		pbmap[in.Tag] = in
	}
	without := protocol.Clone(root)
	delete(without, "inbounds")
	global, _ := json.Marshal(without)
	p.Inbounds, p.BaseHash = pbmap, sha256.Sum256(global)
	p.Outbounds = map[string]*core.OutboundHandlerConfig{}
	for _, out := range pb.Outbound {
		p.Outbounds[out.Tag] = out
	}
	return p, nil
}
