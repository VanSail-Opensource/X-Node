package xray

import (
	"errors"
	"sort"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const coreDNSTag = "_xnode_dns_core"

// scopedDNS intercepts only authenticated managed listeners. Core DNS queries
// carry a separate tag and use a dedicated freedom outbound before user rules.
func scopedDNS(root map[string]any, outs []any, policy protocol.DNSPolicy, users []protocol.User) ([]any, error) {
	if !policy.Redirect {
		return outs, nil
	}
	resolver, _ := root["dns"].(map[string]any)
	if resolver == nil {
		resolver = map[string]any{}
	}
	servers, _ := resolver["servers"].([]any)
	if len(servers) == 0 {
		if policy.Mode != "smartdns" {
			return nil, errors.New("DNS interception requires configured Xray DNS servers")
		}
		// Legacy SmartDNS remains an externally managed resolver. Never change
		// its process, configuration or service ownership during an upgrade.
		resolver["servers"] = []any{"127.0.0.1"}
	}
	resolver["tag"] = coreDNSTag
	root["dns"] = resolver
	tags := map[string]bool{}
	for _, user := range users {
		for _, tag := range user.InboundTags {
			tags[tag] = true
		}
	}
	managed := make([]string, 0, len(tags))
	for tag := range tags {
		managed = append(managed, tag)
	}
	sort.Strings(managed)
	outs = append(outs,
		map[string]any{"protocol": "freedom", "tag": coreDNSTag, "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"0.0.0.0/0", "::/0"}}}}},
		map[string]any{"protocol": "dns", "tag": "_xnode_dns_out"},
	)
	routing, _ := root["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	rules, _ := routing["rules"].([]any)
	guards := []any{map[string]any{"type": "field", "inboundTag": []string{coreDNSTag}, "outboundTag": coreDNSTag}}
	if len(managed) > 0 {
		guards = append(guards, map[string]any{"type": "field", "inboundTag": managed, "port": "53", "network": "tcp,udp", "outboundTag": "_xnode_dns_out"})
	}
	routing["rules"] = append(guards, rules...)
	root["routing"] = routing
	return outs, nil
}
