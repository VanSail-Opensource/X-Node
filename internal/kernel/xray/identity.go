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

func unsafeOutbound(raw any) bool {
	out, _ := raw.(map[string]any)
	if out["proxySettings"] != nil || out["mux"] != nil {
		return true
	}
	stream, _ := out["streamSettings"].(map[string]any)
	socket, _ := stream["sockopt"].(map[string]any)
	if socket["dialerProxy"] != nil {
		return true
	}
	settings, _ := out["settings"].(map[string]any)
	text := stringJSON(settings)
	return out["protocol"] == "loopback" || strings.Contains(text, `"reverse"`)
}

func stringJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
