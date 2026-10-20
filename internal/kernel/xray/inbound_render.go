package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func renderInbounds(c protocol.Config, root map[string]any, auxiliary map[string]bool) (map[string]string, map[string]string, error) {
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return nil, nil, errors.New("inbounds must be an array")
	}
	seen := map[string]bool{}
	base := map[string]string{}
	epochs := map[string]string{}
	if len(inbounds) > 128 {
		return nil, nil, errors.New("too many managed inbounds")
	}
	for _, raw := range inbounds {
		in, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, errors.New("invalid inbound")
		}
		tag, _ := in["tag"].(string)
		if !protocol.ValidName(tag) || seen[tag] {
			return nil, nil, errors.New("inbound tags must be unique")
		}
		seen[tag] = true
		proto, _ := in["protocol"].(string)
		switch proto {
		case "vmess", "vless", "trojan", "shadowsocks", "hysteria", "socks", "http", "mixed", "dokodemo-door", "tunnel":
		default:
			return nil, nil, fmt.Errorf("unsupported managed inbound protocol %s", proto)
		}
		settings, _ := in["settings"].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			in["settings"] = settings
		}
		for _, key := range []string{"clients", "users", "accounts"} {
			if _, exists := settings[key]; exists {
				return nil, nil, errors.New("inbound account lists belong in managed users")
			}
		}
		if proto == "shadowsocks" {
			if _, exists := settings["password"]; exists { /* SS2022 server keys are native settings, never user identities. */
			}
		}
		stream, _ := in["streamSettings"].(map[string]any)
		if stream == nil {
			stream = map[string]any{}
			in["streamSettings"] = stream
		}
		if profile := c.InboundCertificates[tag]; profile != "" {
			if stream["security"] == "reality" {
				return nil, nil, errors.New("REALITY cannot use a TLS certificate profile")
			}
			stream["security"] = "tls"
			tls, _ := stream["tlsSettings"].(map[string]any)
			if tls == nil {
				tls = map[string]any{}
			}
			tls["certificates"] = []any{map[string]any{"certificateFile": c.Certificates[profile].Config.CertFile, "keyFile": c.Certificates[profile].Config.KeyFile}}
			stream["tlsSettings"] = tls
		}
		if proto == "trojan" && stream["security"] != "tls" && stream["security"] != "reality" {
			return nil, nil, errors.New("Trojan requires TLS or REALITY")
		}
		if proto == "hysteria" && stream["security"] != "tls" {
			return nil, nil, errors.New("Hysteria requires TLS")
		}
		// The upstream file/OCSP ticker mutates certificates concurrently with
		// handshakes. Certificate refresh is serialized by the agent instead.
		if tlsSettings, ok := stream["tlsSettings"].(map[string]any); ok {
			if certificates, ok := tlsSettings["certificates"].([]any); ok {
				for _, raw := range certificates {
					certificate, ok := raw.(map[string]any)
					if !ok {
						return nil, nil, errors.New("invalid TLS certificate")
					}
					certificate["oneTimeLoading"] = true
				}
			}
		}
		if c.Torrent.Enabled {
			sniff, _ := in["sniffing"].(map[string]any)
			if sniff == nil {
				sniff = map[string]any{}
			}
			sniff["enabled"], sniff["metadataOnly"] = true, false
			in["sniffing"] = sniff
		}
		identity, err := listenerIdentity(in)
		if err != nil {
			return nil, nil, err
		}
		b, _ := json.Marshal(identity)
		base[tag] = string(b)
		if auxiliary[tag] {
			continue
		}
		epochHash := sha256.Sum256(b)
		epochs[tag] = hex.EncodeToString(epochHash[:12])
		clients := []any{}
		for _, u := range c.Users {
			eligible := false
			for _, t := range u.InboundTags {
				if t == tag {
					eligible = true
					break
				}
			}
			if !eligible {
				continue
			}
			account, err := accountFor(proto, tag, settings, u)
			if err != nil {
				return nil, nil, err
			}
			account["email"] = protocol.UserEmail(u, tag) + "@" + epochs[tag]
			if proto == "socks" || proto == "mixed" || proto == "http" {
				account["user"] = account["email"]
			}
			clients = append(clients, account)
			transit, err := transitAccounts(proto, tag, settings, u, epochs[tag])
			if err != nil {
				return nil, nil, err
			}
			clients = append(clients, transit...)
		}
		if proto == "socks" || proto == "mixed" || proto == "http" {
			settings["accounts"] = clients
			if proto != "http" {
				settings["auth"] = "password"
			}
		} else {
			settings["clients"] = clients
		}
	}
	for _, u := range c.Users {
		for _, tag := range u.InboundTags {
			if !seen[tag] {
				return nil, nil, errors.New("user references unknown inbound")
			}
		}
	}
	for tag := range c.InboundCertificates {
		if !seen[tag] {
			return nil, nil, errors.New("certificate references unknown inbound")
		}
	}

	return base, epochs, nil
}
