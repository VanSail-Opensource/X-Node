package xray

import "errors"

const domainBlockTag = "_xnode_domain_block"

func applyDomainBlocks(root map[string]any, domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	outs, _ := root["outbounds"].([]any)
	if len(outs) == 0 {
		outs = []any{map[string]any{"tag": "_xnode_domain_direct", "protocol": "freedom"}}
	}
	for _, raw := range outs {
		if out, _ := raw.(map[string]any); out["tag"] == domainBlockTag {
			return errors.New("reserved domain-block outbound tag")
		}
	}
	root["outbounds"] = append(outs, map[string]any{"tag": domainBlockTag, "protocol": "blackhole", "settings": map[string]any{}})
	routing, _ := root["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
		root["routing"] = routing
	}
	rules, _ := routing["rules"].([]any)
	routing["rules"] = append([]any{map[string]any{"type": "field", "domain": domains, "outboundTag": domainBlockTag}}, rules...)
	return nil
}
