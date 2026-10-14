package xray

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

func TestManagedSS2022AccountsBuildWithoutPerUserMethod(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			serverKey, userKey := base64.StdEncoding.EncodeToString(make([]byte, size)), base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, size-1)...))
			config := protocol.Config{Xray: json.RawMessage(fmt.Sprintf(`{"inbounds":[{"tag":"ss","port":8388,"protocol":"shadowsocks","settings":{"method":%q,"password":%q}}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}`, method, serverKey)), Users: []protocol.User{{ID: 1, UUID: testUUID, InboundTags: []string{"ss"}, Credentials: map[string]json.RawMessage{"ss": json.RawMessage(fmt.Sprintf(`{"password":%q}`, userKey))}}}}
			prepared, err := Prepare(config)
			if err != nil {
				t.Fatal(err)
			}
			inbound := prepared.Native["inbounds"].([]any)[0].(map[string]any)
			client := inbound["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
			if _, exists := client["method"]; exists {
				t.Fatal("method leaked onto SS2022 account")
			}
			if client["password"] != userKey {
				t.Fatal("user credential changed")
			}
		})
	}
}

func TestManagedSS2022CredentialsAuthenticateNativeStreams(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			serverKey, userKey := base64.StdEncoding.EncodeToString(make([]byte, size)), base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, size-1)...))
			config, port := testConfig(t)
			var native map[string]any
			if err := json.Unmarshal(config.Xray, &native); err != nil {
				t.Fatal(err)
			}
			inbound := native["inbounds"].([]any)[0].(map[string]any)
			inbound["protocol"] = "shadowsocks"
			inbound["settings"] = map[string]any{"method": method, "password": serverKey}
			var err error
			config.Xray, err = json.Marshal(native)
			if err != nil {
				t.Fatal(err)
			}
			config.Users[0].Credentials = map[string]json.RawMessage{"in": json.RawMessage(fmt.Sprintf(`{"password":%q}`, userKey))}
			registry := sessions.New()
			registry.SetUsers(config.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err = runtime.Apply(ctx, config); err != nil {
				t.Fatal(err)
			}
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("authenticated")) }))
			defer target.Close()
			peer := map[string]any{"tag": "peer", "protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": port, "method": method, "password": serverKey + ":" + userKey}}}}
			client, closeClient, err := HTTPClient(ctx, []any{peer}, "peer")
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient()
			response, err := client.Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "authenticated" {
				t.Fatalf("authentication failed: status=%d,error=%v", response.StatusCode, err)
			}
		})
	}
}
