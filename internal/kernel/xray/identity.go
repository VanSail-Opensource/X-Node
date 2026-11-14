package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
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
		Mux      *json.RawMessage `json:"mux"`
		Settings json.RawMessage  `json:"settings"`
	}
	value, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(value, &out) != nil {
		return true
	}
	if out.Proxy != nil || out.Mux != nil || len(dependencies) > 0 {
		return true
	}
	return strings.EqualFold(out.Protocol, "loopback") || strings.Contains(strings.ToLower(string(out.Settings)), `"reverse"`)
}
