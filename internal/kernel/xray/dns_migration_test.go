package xray

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestNativePreparationMigratesDeprecatedModeBeforeRendering(t *testing.T) {
	config, _ := testConfig(t)
	original := append([]byte(nil), config.Xray...)
	config.DNS = protocol.DNSPolicy{Mode: "smartdns", Redirect: true, Upstreams: []string{"203.0.113.53"}}
	prepared, err := Prepare(config)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := prepared.Native["dns"].(map[string]any)
	if prepared.Source.DNS.Mode != "xray" || !reflect.DeepEqual(resolver["servers"], []any{"127.0.0.1"}) || !bytes.Equal(config.Xray, original) {
		t.Fatal("native preparation changed DNS", resolver)
	}
}

func TestScopedDNSRendererHasNoModeDependentFallback(t *testing.T) {
	for _, mode := range []string{"", "xray", "smartdns"} {
		if _, err := scopedDNS(map[string]any{}, nil, protocol.DNSPolicy{Mode: mode, Redirect: true}, nil); err == nil {
			t.Fatal("runtime selected a resolver from deprecated mode", mode)
		}
	}
}
