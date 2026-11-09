package xray

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/proxy/hysteria"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// The Xray TCP worker reads the Hysteria QUIC validator from the concrete
// *hysteria.Server. Wrapping that inbound in the observation layer hides the
// concrete type and leaves the validator nil, so the listener cannot start.
func TestHysteriaInboundStaysUnwrappedForTransportValidator(t *testing.T) {
	document := map[string]any{
		"inbounds": []any{map[string]any{
			"tag":      "hy2",
			"listen":   "0.0.0.0",
			"port":     10000,
			"protocol": "hysteria",
			"settings": map[string]any{"version": 2},
			"streamSettings": map[string]any{
				"network":          "hysteria",
				"security":         "tls",
				"tlsSettings":      map[string]any{"serverName": "example.test", "alpn": []any{"h3"}},
				"hysteriaSettings": map[string]any{"version": 2},
			},
		}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(protocol.Config{Xray: raw})
	if err != nil {
		t.Fatal(err)
	}
	handler, ok := prepared.Inbounds["hy2"]
	if !ok {
		t.Fatal("hysteria inbound missing from prepared configuration")
	}
	object, err := handler.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if _, wrapped := object.(*InboundConfig); wrapped {
		t.Fatal("hysteria inbound must stay unwrapped for the transport validator")
	}
	if _, server := object.(*hysteria.ServerConfig); !server {
		t.Fatalf("unexpected hysteria proxy settings %T", object)
	}
}
