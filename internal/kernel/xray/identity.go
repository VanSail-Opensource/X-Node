package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

// listenerIdentity includes resolved file bytes, excluding accounts and globals.
func listenerIdentity(value any) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			if k == "certificateFile" || k == "keyFile" {
				path, ok := item.(string)
				if !ok {
					return nil, errors.New("invalid TLS file path")
				}
				file, err := os.Open(path)
				if err != nil {
					return nil, errors.New("cannot read TLS material")
				}
				h := sha256.New()
				n, err := io.Copy(h, io.LimitReader(file, 8<<20+1))
				closeErr := file.Close()
				if err != nil || closeErr != nil || n > 8<<20 {
					return nil, errors.New("invalid TLS material")
				}
				out[k] = path + ":" + hex.EncodeToString(h.Sum(nil))
				continue
			}
			item, err := listenerIdentity(item)
			if err != nil {
				return nil, err
			}
			out[k] = item
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			item, err := listenerIdentity(x)
			if err != nil {
				return nil, err
			}
			out[i] = item
		}
		return out, nil
	}
	return value, nil
}

func unsafeOutbound(raw any, dependencies []string) bool {
	var out struct {
		Protocol string           `json:"protocol"`
		Proxy    *json.RawMessage `json:"proxySettings"`
		Mux      *conf.MuxConfig  `json:"mux"`
		Settings json.RawMessage  `json:"settings"`
	}
	value, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(value, &out) != nil || ambiguousOutboundMux(raw) {
		return true
	}
	if out.Proxy != nil || len(dependencies) > 0 {
		return true
	}
	if out.Mux != nil {
		// Carpool can explicitly emit enabled:false. The pinned native
		// handler never creates a mux client for that configuration.
		mux, err := out.Mux.Build()
		if err != nil || mux.Enabled {
			return true
		}
	}
	return strings.EqualFold(out.Protocol, "loopback") || strings.Contains(strings.ToLower(string(out.Settings)), `"reverse"`)
}

func ambiguousOutboundMux(raw any) bool {
	fields, _ := raw.(map[string]any)
	found := false
	for field, value := range fields {
		if !strings.EqualFold(field, "mux") {
			continue
		}
		if found {
			return true
		}
		found = true

		// The native JSON decoder accepts case-insensitive field names. A
		// case-variant duplicate in the parsed document is not safe evidence
		// that multiplexing is disabled.
		options, _ := value.(map[string]any)
		seen := make(map[string]bool, len(options))
		for key := range options {
			switch name := strings.ToLower(key); name {
			case "enabled", "concurrency", "xudpconcurrency", "xudpproxyudp443":
				if seen[name] {
					return true
				}
				seen[name] = true
			}
		}
	}
	return false
}
