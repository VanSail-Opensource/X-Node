package xray

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestNativePreparationPreservesExplicitResolverWithoutChangingCaller(t *testing.T) {
	config, _ := testConfig(t)
	var native map[string]any
	if err := json.Unmarshal(config.Xray, &native); err != nil {
		t.Fatal(err)
	}
	native["dns"] = map[string]any{"servers": []string{"127.0.0.1"}}
	config.Xray, _ = json.Marshal(native)
	original := append([]byte(nil), config.Xray...)
	config.DNS = protocol.DNSPolicy{Redirect: true}
	prepared, err := Prepare(config)
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := prepared.Native["dns"].(map[string]any)
	if !reflect.DeepEqual(resolver["servers"], []any{"127.0.0.1"}) || !bytes.Equal(config.Xray, original) {
		t.Fatal("native preparation changed DNS", resolver)
	}
}

func TestScopedDNSRendererRequiresExplicitNativeServers(t *testing.T) {
	if _, err := scopedDNS(map[string]any{}, nil, protocol.DNSPolicy{Redirect: true}, nil); err == nil {
		t.Fatal("runtime selected an implicit resolver")
	}
}
