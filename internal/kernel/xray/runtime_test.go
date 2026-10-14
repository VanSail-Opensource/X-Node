package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testUUID = "550e8400-e29b-41d4-a716-446655440000"

func testConfig(t *testing.T) (protocol.Config, int) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return protocol.Config{Xray: json.RawMessage(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"tag":"in","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none"}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]}}]}`, port)), Users: []protocol.User{{ID: 1, UUID: testUUID, InboundTags: []string{"in"}}}}, port
}
func testClient(t *testing.T, port int, uuid string, mux bool) *http.Client {
	t.Helper()
	peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": uuid, "encryption": "none"}}}}}}
	if mux {
		peer["mux"] = map[string]any{"enabled": true, "concurrency": 8}
	}
	client, close, e := HTTPClient(context.Background(), []any{peer}, "peer")
	if e != nil {
		t.Fatal(e)
	}
	client.Timeout = 2 * time.Second
	t.Cleanup(close)
	return client
}
func requestOK(client *http.Client, url string) bool {
	response, e := client.Get(url)
	if e != nil {
		return false
	}
	defer response.Body.Close()
	b, e := io.ReadAll(response.Body)
	return e == nil && response.StatusCode == 200 && string(b) == "works"
}
func TestRealVLESSRotationEmptySnapshotAndAccounting(t *testing.T) {
	for _, mux := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%t", mux), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("works")) }))
			defer server.Close()
			registry := sessions.New()
			runtime := New(registry)
			var logOutput bytes.Buffer
			stream := nlog.NewStream(&logOutput)
			defer runtime.Stop()
			c, port := testConfig(t)
			registry.SetUsers(c.Users)
			if e := runtime.Apply(context.Background(), c); e != nil {
				t.Fatal(e)
			}
			old := testClient(t, port, testUUID, mux)
			if !requestOK(old, server.URL) {
				entries, _ := stream.Drain()
				t.Logf("summary=%+v counters=%+v logs=%+v", registry.Summary(), registry.Counters(), entries)
				t.Fatal("fresh user cannot connect")
			}
			if registry.Counters()[1][0] == 0 || registry.Counters()[1][1] == 0 {
				t.Fatal("traffic not accounted")
			}
			oldInstance := runtime.instance
			c.Users[0].UUID = "550e8400-e29b-41d4-a716-446655440001"
			registry.SetUsers(c.Users)
			if e := runtime.Apply(context.Background(), c); e != nil {
				t.Fatal(e)
			}
			if runtime.instance != oldInstance {
				t.Fatal("user rotation restarted listener")
			}
			if requestOK(old, server.URL) {
				t.Fatal("previous credential or mux transport remained usable")
			}
			fresh := testClient(t, port, c.Users[0].UUID, mux)
			if !requestOK(fresh, server.URL) {
				t.Fatal("replacement credential rejected")
			}
			c.Users = []protocol.User{}
			registry.SetUsers(c.Users)
			if e := runtime.Apply(context.Background(), c); e != nil {
				t.Fatal(e)
			}
			if requestOK(fresh, server.URL) {
				t.Fatal("empty snapshot retained user")
			}
		})
	}
}
func TestNativeFieldsAndOutboundCycles(t *testing.T) {
	c, _ := testConfig(t)
	var root map[string]any
	_ = json.Unmarshal(c.Xray, &root)
	root["dns"] = map[string]any{"servers": []any{"localhost"}}
	root["fakeDns"] = []any{map[string]any{"ipPool": "198.18.0.0/15", "poolSize": 100}}
	root["observatory"] = map[string]any{"subjectSelector": []any{"direct"}, "probeURL": "https://example.com", "probeInterval": "60s"}
	c.Xray, _ = json.Marshal(root)
	p, e := Prepare(c)
	if e != nil {
		t.Fatal(e)
	}
	if p.Native["dns"] == nil || p.Native["fakeDns"] == nil || p.Native["observatory"] == nil {
		t.Fatal("native fields lost")
	}
	root["outbounds"] = []any{map[string]any{"tag": "a", "protocol": "freedom", "proxySettings": map[string]any{"tag": "b"}}, map[string]any{"tag": "b", "protocol": "freedom", "proxySettings": map[string]any{"tag": "a"}}}
	c.Xray, _ = json.Marshal(root)
	if _, e = Prepare(c); e == nil {
		t.Fatal("outbound cycle accepted")
	}
}
