package xray

import (
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"sort"
)

func validateOutbounds(outs []any) error {
	if len(outs) > 256 {
		return errors.New("too many outbounds")
	}
	edges := map[string][]string{}
	for _, raw := range outs {
		out, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid outbound")
		}
		tag, _ := out["tag"].(string)
		if !protocol.ValidName(tag) {
			return errors.New("outbound tag is required")
		}
		if _, exists := edges[tag]; exists {
			return errors.New("duplicate outbound tag")
		}
		dependencies, err := outboundDependencies(out)
		if err != nil {
			return err
		}
		edges[tag] = dependencies
	}
	color := map[string]int{}
	var visit func(string) error
	visit = func(tag string) error {
		if color[tag] == 1 {
			return errors.New("outbound dependency cycle")
		}
		if color[tag] == 2 {
			return nil
		}
		if _, ok := edges[tag]; !ok {
			return errors.New("unknown outbound dependency")
		}
		color[tag] = 1
		for _, next := range edges[tag] {
			if err := visit(next); err != nil {
				return err
			}
		}
		color[tag] = 2
		return nil
	}
	keys := make([]string, 0, len(edges))
	for tag := range edges {
		keys = append(keys, tag)
	}
	sort.Strings(keys)
	for _, tag := range keys {
		if err := visit(tag); err != nil {
			return err
		}
	}
	return nil
}

func outboundDependencies(out any) ([]string, error) {
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return protocol.NativeOutboundDependencies(raw)
}
