package xray

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	nativetls "github.com/xtls/xray-core/transport/internet/tls"
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
}

func validateTLSMaterial(settings *serial.TypedMessage) error {
	obj, e := settings.GetInstance()
	if e != nil {
		return errors.New("invalid receiver settings")
	}
	receiver, ok := obj.(*proxyman.ReceiverConfig)
	if !ok || receiver.StreamSettings == nil {
		return nil
	}
	for _, raw := range receiver.StreamSettings.SecuritySettings {
		obj, e := raw.GetInstance()
		if e != nil {
			return errors.New("invalid security settings")
		}
		config, ok := obj.(*nativetls.Config)
		if !ok {
			continue
		}
		for _, certificate := range config.Certificate {
			if certificate.Usage == nativetls.Certificate_ENCIPHERMENT {
				if _, e = tls.X509KeyPair(certificate.Certificate, certificate.Key); e != nil {
					return errors.New("invalid TLS certificate or private key pair")
				}
			}
		}
	}
	return nil
}

func Prepare(c protocol.Config) (*Prepared, error) {
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
	identityRoot := protocol.Clone(root)
	delete(identityRoot, "inbounds")
	identityJSON, _ := json.Marshal(identityRoot)
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return nil, errors.New("inbounds must be an array")
	}
	seen := map[string]bool{}
	base := map[string]string{}
	epochs := map[string]string{}
	if len(inbounds) > 128 {
		return nil, errors.New("too many managed inbounds")
	}
	for _, raw := range inbounds {
		in, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid inbound")
		}
		tag, _ := in["tag"].(string)
		if !protocol.ValidName(tag) || seen[tag] {
			return nil, errors.New("inbound tags must be unique")
		}
		seen[tag] = true
		proto, _ := in["protocol"].(string)
		switch proto {
		case "vmess", "vless", "trojan", "shadowsocks", "hysteria", "socks", "http", "mixed", "dokodemo-door", "tunnel":
		default:
			return nil, fmt.Errorf("unsupported managed inbound protocol %s", proto)
		}
		settings, _ := in["settings"].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			in["settings"] = settings
		}
		for _, key := range []string{"clients", "users", "accounts"} {
			if _, exists := settings[key]; exists {
				return nil, errors.New("inbound account lists belong in managed users")
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
				return nil, errors.New("REALITY cannot use a TLS certificate profile")
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
			return nil, errors.New("Trojan requires TLS or REALITY")
		}
		if proto == "hysteria" && stream["security"] != "tls" {
			return nil, errors.New("Hysteria requires TLS")
		}
		// The upstream file/OCSP ticker mutates certificates concurrently with
		// handshakes. Certificate refresh is serialized by the agent instead.
		if tlsSettings, ok := stream["tlsSettings"].(map[string]any); ok {
			if certificates, ok := tlsSettings["certificates"].([]any); ok {
				for _, raw := range certificates {
					certificate, ok := raw.(map[string]any)
					if !ok {
						return nil, errors.New("invalid TLS certificate")
					}
					certificate["oneTimeLoading"] = true
				}
			}
		}
		b, _ := json.Marshal(in)
		base[tag] = string(b)
		if auxiliary[tag] {
			continue
		}
		epochHash := sha256.Sum256(append(append([]byte(nil), identityJSON...), b...))
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
				return nil, err
			}
			account["email"] = protocol.UserEmail(u, tag) + "@" + epochs[tag]
			if proto == "socks" || proto == "mixed" || proto == "http" {
				account["user"] = account["email"]
			}
			clients = append(clients, account)
		}
		if proto == "socks" || proto == "mixed" || proto == "http" {
			settings["accounts"] = clients
			if proto != "http" {
				settings["auth"] = "password"
			}
		} else {
			settings["clients"] = clients
		}
		if c.Torrent.Enabled {
			sniff, _ := in["sniffing"].(map[string]any)
			if sniff == nil {
				sniff = map[string]any{}
			}
			sniff["enabled"] = true
			sniff["metadataOnly"] = false
			in["sniffing"] = sniff
		}
	}
	for _, u := range c.Users {
		for _, tag := range u.InboundTags {
			if !seen[tag] {
				return nil, errors.New("user references unknown inbound")
			}
		}
	}
	for tag := range c.InboundCertificates {
		if !seen[tag] {
			return nil, errors.New("certificate references unknown inbound")
		}
	}
	outs, _ := root["outbounds"].([]any)
	if len(outs) == 0 {
		outs = []any{map[string]any{"protocol": "freedom", "tag": "direct"}}
	}
	if err := validateOutbounds(outs); err != nil {
		return nil, err
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
		return nil, err
	}
	root["inbounds"] = inbounds
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
	b, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	pb, err := confserial.LoadJSONConfig(bytes.NewReader(b))
	if err != nil {
		return nil, errors.New("Xray configuration validation failed")
	}
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
	}
	pbmap := map[string]*core.InboundHandlerConfig{}
	for _, in := range pb.Inbound {
		if !auxiliary[in.Tag] {
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
	return &Prepared{Source: protocol.Clone(c), Native: root, Core: pb, Inbounds: pbmap, BaseHash: sha256.Sum256(global), InboundBase: base, Epochs: epochs, Auxiliary: auxiliary}, nil
}

func accountFor(proto, tag string, settings map[string]any, u protocol.User) (map[string]any, error) {
	account := map[string]any{}
	if raw := u.Credentials[tag]; len(raw) > 0 {
		if json.Unmarshal(raw, &account) != nil || account == nil {
			return nil, errors.New("invalid native account")
		}
	}
	switch proto {
	case "vless", "vmess":
		if _, ok := account["id"]; !ok {
			account["id"] = u.UUID
		}
	case "trojan":
		if _, ok := account["password"]; !ok {
			account["password"] = u.UUID
		}
	case "hysteria":
		if _, ok := account["auth"]; !ok {
			account["auth"] = u.UUID
		}
	case "shadowsocks":
		method, _ := settings["method"].(string)
		ss2022 := strings.HasPrefix(method, "2022-")
		if ss2022 {
			if value, exists := account["method"]; exists && value != "" {
				return nil, errors.New("SS2022 user accounts must omit the method")
			}
			delete(account, "method")
		}
		if _, ok := account["password"]; !ok {
			if ss2022 {
				h := sha256.Sum256([]byte(u.UUID))
				size := 32
				if strings.Contains(method, "aes-128") {
					size = 16
				}
				account["password"] = base64.StdEncoding.EncodeToString(h[:size])
			} else {
				account["password"] = u.UUID
			}
		}
		if _, ok := account["method"]; !ok && !ss2022 {
			account["method"] = settings["method"]
		}
	case "socks", "mixed", "http":
		account["user"] = protocol.UserEmail(u, tag)
		if _, ok := account["pass"]; !ok {
			account["pass"] = u.UUID
		}
	}
	account["email"] = protocol.UserEmail(u, tag)
	account["level"] = 0
	return account, nil
}
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
		edges[tag] = nil
		proxy, _ := out["proxySettings"].(map[string]any)
		if target, _ := proxy["tag"].(string); target != "" {
			edges[tag] = append(edges[tag], target)
		}
		stream, _ := out["streamSettings"].(map[string]any)
		sock, _ := stream["sockopt"].(map[string]any)
		if target, _ := sock["dialerProxy"].(string); target != "" {
			edges[tag] = append(edges[tag], target)
		}
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
