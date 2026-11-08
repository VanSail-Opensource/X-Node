package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNativeEnvironmentRejectsProcessInjection(t *testing.T) {
	for _, key := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "GODEBUG", "PYTHONPATH", "ENV", "xray.location.asset", "XRAY_UNKNOWN", "XRAY_BUF_READV="} {
		raw, err := json.Marshal(map[string]any{"env": map[string]string{key: "/untrusted"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateNativePolicies(Config{Xray: raw}); err == nil {
			t.Fatalf("accepted unsafe key %s", key)
		}
	}
	for _, env := range []any{[]string{"LD_PRELOAD=x"}, map[string]any{"XRAY_BUF_READV": true}, map[string]string{"XRAY_LOCATION_ASSET": "bad\x00path"}, map[string]string{"XRAY_LOCATION_CERT": strings.Repeat("x", 4097)}} {
		raw, err := json.Marshal(map[string]any{"env": env})
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateNativePolicies(Config{Xray: raw}); err == nil {
			t.Fatal("accepted malformed environment")
		}
	}
	for _, raw := range []string{`{}`, `{"env":null}`, `{"env":{"XRAY_LOCATION_ASSET":"/managed/assets","XRAY_BUF_READV":"true"}}`} {
		if err := ValidateNativePolicies(Config{Xray: json.RawMessage(raw)}); err != nil {
			t.Fatal(err)
		}
	}
}
