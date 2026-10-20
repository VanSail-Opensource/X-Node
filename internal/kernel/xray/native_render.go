package xray

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func renderGlobals(c protocol.Config, root map[string]any) error {
	var err error
	outs, _ := root["outbounds"].([]any)
	if len(outs) == 0 {
		outs = []any{map[string]any{"protocol": "freedom", "tag": "direct"}}
	}
	if err := validateOutbounds(outs); err != nil {
		return err
	}
	if c.Torrent.Enabled {
		outs = append(outs, map[string]any{"tag": "_xnode_torrent", "protocol": "blackhole"})
		routing, _ := root["routing"].(map[string]any)
		if routing == nil {
			routing = map[string]any{}
		}
		rules, _ := routing["rules"].([]any)
		routing["rules"] = append([]any{map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "_xnode_torrent"}}, rules...)
		root["routing"] = routing
	}
	outs, err = scopedDNS(root, outs, c.DNS, c.Users)
	if err != nil {
		return err
	}
	root["outbounds"] = outs
	root["stats"] = map[string]any{}
	policy, _ := root["policy"].(map[string]any)
	if policy == nil {
		policy = map[string]any{}
	}
	levels, _ := policy["levels"].(map[string]any)
	if levels == nil {
		levels = map[string]any{}
	}
	zero, _ := levels["0"].(map[string]any)
	if zero == nil {
		zero = map[string]any{}
	}
	zero["statsUserUplink"] = true
	zero["statsUserDownlink"] = true
	levels["0"] = zero
	policy["levels"] = levels
	root["policy"] = policy
	if err := applyDomainBlocks(root, c.BlockedDomains); err != nil {
		return err
	}
	if root["routing"] == nil {
		root["routing"] = map[string]any{}
	}

	return nil
}
