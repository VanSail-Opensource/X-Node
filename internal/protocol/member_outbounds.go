package protocol

import (
	"encoding/json"
	"errors"
	"net/netip"
)

var reservedProxyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// PublicProxyAddress admits literal public addresses only, preventing node DNS rebinding.
func PublicProxyAddress(raw string) bool {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range reservedProxyPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// ValidateMemberOutbounds guards master-generated member proxies independently on the agent.
func ValidateMemberOutbounds(raw json.RawMessage, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	var root struct {
		Outbounds []struct {
			Tag      string         `json:"tag"`
			Protocol string         `json:"protocol"`
			Settings map[string]any `json:"settings"`
			Stream   map[string]any `json:"streamSettings"`
			Proxy    any            `json:"proxySettings"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(raw, &root) != nil {
		return errors.New("invalid member outbound configuration")
	}
	wanted := map[string]bool{}
	owned := map[string]bool{}
	for _, tag := range tags {
		if !ValidName(tag) || wanted[tag] {
			return errors.New("invalid or duplicate member outbound tag")
		}
		wanted[tag] = true
		owned[tag] = true
	}
	for _, out := range root.Outbounds {
		if !wanted[out.Tag] {
			continue
		}
		delete(wanted, out.Tag)
		if memberLocalFile(out.Stream) || memberLocalFile(out.Settings) {
			return errors.New("member proxy cannot reference node-local files")
		}
		if out.Proxy != nil {
			chain, ok := out.Proxy.(map[string]any)
			if !ok {
				return errors.New("invalid member proxy chain")
			}
			target, _ := chain["tag"].(string)
			if !owned[target] {
				return errors.New("member proxy chain references a foreign tag")
			}
			for key := range chain {
				if key != "tag" && key != "transportLayer" {
					return errors.New("unsupported member proxy chain setting")
				}
			}
		}
		if socket, ok := out.Stream["sockopt"].(map[string]any); ok && len(socket) > 0 {
			target, _ := socket["dialerProxy"].(string)
			if len(socket) != 1 || !owned[target] {
				return errors.New("member socket overrides are not permitted")
			}
		}
		if out.Protocol == "hysteria" {
			address, _ := out.Settings["address"].(string)
			if !PublicProxyAddress(address) {
				return errors.New("member proxy endpoint must be a literal public address")
			}
			continue
		}
		key := "servers"
		switch out.Protocol {
		case "vless", "vmess":
			key = "vnext"
		case "trojan", "shadowsocks", "socks", "http", "hysteria":
		default:
			return errors.New("unsupported member proxy protocol")
		}
		servers, ok := out.Settings[key].([]any)
		if !ok || len(servers) != 1 {
			return errors.New("member proxy needs exactly one endpoint")
		}
		server, ok := servers[0].(map[string]any)
		if !ok {
			return errors.New("invalid member proxy endpoint")
		}
		address, _ := server["address"].(string)
		if !PublicProxyAddress(address) {
			return errors.New("member proxy endpoint must be a literal public address")
		}
	}
	if len(wanted) != 0 {
		return errors.New("member outbound tag is missing")
	}
	return nil
}

func memberLocalFile(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			if key == "certificateFile" || key == "keyFile" || key == "certFile" || key == "caFile" || key == "unix" {
				return true
			}
			if memberLocalFile(item) {
				return true
			}
		}
	case []any:
		for _, item := range value {
			if memberLocalFile(item) {
				return true
			}
		}
	}
	return false
}
