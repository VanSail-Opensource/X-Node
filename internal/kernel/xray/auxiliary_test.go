package xray

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

func TestNativeAuxiliaryForwardingSurvivesManagedUserChanges(t *testing.T) {
	for _, kind := range []string{"dokodemo-door", "tunnel"} {
		t.Run(kind, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("works")) }))
			defer upstream.Close()
			_, target, err := net.SplitHostPort(upstream.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			targetPort, _ := strconv.Atoi(target)
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reserved.Addr().(*net.TCPAddr).Port
			_ = reserved.Close()
			config, _ := testConfig(t)
			var native map[string]any
			_ = json.Unmarshal(config.Xray, &native)
			native["inbounds"] = append(native["inbounds"].([]any), map[string]any{"tag": "utility", "protocol": kind, "listen": "127.0.0.1", "port": port, "settings": map[string]any{"address": "127.0.0.1", "port": targetPort, "network": "tcp"}})
			config.Xray, _ = json.Marshal(native)
			registry := sessions.New()
			registry.SetUsers(config.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err = runtime.Apply(context.Background(), config); err != nil {
				t.Fatal(err)
			}
			instance := runtime.instance
			client := upstream.Client()
			client.Timeout = 3 * time.Second
			url := "http://127.0.0.1:" + strconv.Itoa(port) + "/utility"
			if !requestOK(client, url) {
				t.Fatal("auxiliary forwarding was denied")
			}
			config.Users = []protocol.User{}
			registry.SetUsers(config.Users)
			if err = runtime.Apply(context.Background(), config); err != nil {
				t.Fatal(err)
			}
			if runtime.instance != instance || !requestOK(client, url) {
				t.Fatal("managed revocation interrupted auxiliary listener")
			}
			for _, totals := range registry.Counters() {
				if totals[0] != 0 || totals[1] != 0 {
					t.Fatal("auxiliary bytes charged to a member")
				}
			}
		})
	}
}
