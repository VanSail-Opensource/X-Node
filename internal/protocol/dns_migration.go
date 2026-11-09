package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
)

// NormalizeDNS retires resolver selection while preserving effective legacy DNS.
// SmartDNS's former loopback fallback becomes explicit native Xray configuration
// before the deprecated mode is normalized. Upstreams remains inert wire data.
func (c Config) NormalizeDNS() (Config, error) {
	legacy := c.DNS.Mode == "smartdns"
	if c.DNS.Mode != "" && c.DNS.Mode != "xray" && !legacy {
		return c, errors.New("unsupported resolver mode")
	}
	c.DNS.Mode = "xray"
	if !legacy || !c.DNS.Redirect {
		return c, nil
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(c.Xray, &root) != nil || root == nil {
		return c, errors.New("invalid native configuration for legacy DNS migration")
	}
	var resolver map[string]json.RawMessage
	if raw := bytes.TrimSpace(root["dns"]); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if json.Unmarshal(raw, &resolver) != nil || resolver == nil {
			return c, errors.New("native DNS must be an object")
		}
	}
	if resolver == nil {
		resolver = map[string]json.RawMessage{}
	}
	var servers []json.RawMessage
	if raw := bytes.TrimSpace(resolver["servers"]); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if json.Unmarshal(raw, &servers) != nil {
			return c, errors.New("native DNS servers must be an array")
		}
	}
	if len(servers) > 0 {
		return c, nil
	}
	resolver["servers"] = json.RawMessage(`["127.0.0.1"]`)
	raw, err := json.Marshal(resolver)
	if err != nil {
		return c, err
	}
	root["dns"] = raw
	c.Xray, err = json.Marshal(root)
	return c, err
}
