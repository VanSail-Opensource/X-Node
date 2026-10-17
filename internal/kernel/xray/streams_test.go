package xray

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/xtls/xray-core/core"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
)

func nativeClient(t *testing.T, peer map[string]any) *core.Instance {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{peer}})
	pb, e := confserial.LoadJSONConfig(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	instance, e := core.New(pb)
	if e != nil {
		t.Fatal(e)
	}
	if e = instance.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}
func TestRealUDPAndXUDPAccountingAndExpiry(t *testing.T) {
	for _, mux := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%t", mux), func(t *testing.T) {
			echo, e := net.ListenPacket("udp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer echo.Close()
			go func() {
				b := make([]byte, 2048)
				for {
					n, a, e := echo.ReadFrom(b)
					if e != nil {
						return
					}
					_, _ = echo.WriteTo(b[:n], a)
				}
			}()
			cfg, port := testConfig(t)
			var root map[string]any
			_ = json.Unmarshal(cfg.Xray, &root)
			root["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"connIdle": 1, "uplinkOnly": 0, "downlinkOnly": 0}}}
			cfg.Xray, _ = json.Marshal(root)
			registry := sessions.New()
			registry.SetUsers(cfg.Users)
			r := New(registry)
			defer r.Stop()
			if e = r.Apply(context.Background(), cfg); e != nil {
				t.Fatal(e)
			}
			peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
			if mux {
				peer["mux"] = map[string]any{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}
			}
			client := nativeClient(t, peer)
			packet, e := core.DialUDP(context.Background(), client)
			if e != nil {
				t.Fatal(e)
			}
			defer packet.Close()
			_ = packet.SetDeadline(time.Now().Add(4 * time.Second))
			if _, e = packet.WriteTo([]byte("datagram"), echo.LocalAddr()); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 2048)
			n, _, e := packet.ReadFrom(b)
			if e != nil || string(b[:n]) != "datagram" {
				t.Fatalf("UDP reply: %q %v", b[:n], e)
			}
			awaitMeteredTraffic(t, registry, 1, 8, 8)
			if registry.Summary().Connections[1] != 1 {
				t.Fatal("UDP association did not reserve exactly one slot")
			}
			deadline := time.Now().Add(5 * time.Second)
			for registry.Summary().Connections[1] > 0 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if registry.Summary().Connections[1] != 0 {
				t.Fatal("expired UDP association leaked its slot")
			}
		})
	}
}

func TestRealTLSVisionXHTTPAndREALITYAccounting(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 128<<10)) }))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	target.StartTLS()
	defer target.Close()
	cert := target.TLS.Certificates[0]
	der, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"tls", "vision", "xhttp", "reality-vision"} {
		t.Run(mode, func(t *testing.T) {
			logs := nlog.NewStream(io.Discard)
			cfg, port := testConfig(t)
			var root map[string]any
			_ = json.Unmarshal(cfg.Xray, &root)
			in := root["inbounds"].([]any)[0].(map[string]any)
			serverStream := map[string]any{"security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}}}}
			hash := sha256.Sum256(cert.Certificate[0])
			clientStream := map[string]any{"security": "tls", "tlsSettings": map[string]any{"pinnedPeerCertSha256": hex.EncodeToString(hash[:]), "serverName": "example.com"}}
			user := map[string]any{"id": testUUID, "encryption": "none"}
			if mode == "vision" || mode == "reality-vision" {
				cfg.Users[0].Credentials = map[string]json.RawMessage{"in": json.RawMessage(fmt.Sprintf(`{"id":%q,"flow":"xtls-rprx-vision"}`, testUUID))}
				user["flow"] = "xtls-rprx-vision"
			}
			if mode == "xhttp" {
				serverStream["network"] = "xhttp"
				clientStream["network"] = "xhttp"
				serverStream["xhttpSettings"] = map[string]any{"path": "/stream"}
				clientStream["xhttpSettings"] = map[string]any{"path": "/stream"}
			}
			if mode == "reality-vision" {
				key, e := ecdh.X25519().GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				serverStream = map[string]any{"security": "reality", "realitySettings": map[string]any{"target": target.Listener.Addr().String(), "serverNames": []string{"example.com"}, "privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"1234567890abcdef"}}}
				clientStream = map[string]any{"security": "reality", "realitySettings": map[string]any{"fingerprint": "hellochrome_133", "serverName": "example.com", "password": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "1234567890abcdef"}}
			}
			in["streamSettings"] = serverStream
			cfg.Xray, _ = json.Marshal(root)
			registry := sessions.New()
			registry.SetUsers(cfg.Users)
			r := New(registry)
			defer r.Stop()
			if e = r.Apply(context.Background(), cfg); e != nil {
				t.Fatal(e)
			}
			peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{user}}}}, "streamSettings": clientStream}
			client, close, e := HTTPClient(context.Background(), []any{peer}, "peer")
			if e != nil {
				entries, _ := logs.Drain()
				for _, entry := range entries {
					if strings.Contains(entry.Text, "REALITY") || strings.Contains(entry.Text, "handshake") {
						t.Log(entry.Text)
					}
				}
				t.Fatal(e)
			}
			defer close()
			// The fixture endpoint is self-signed; peer TLS/REALITY authentication is independent.
			client.Transport.(*http.Transport).TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig
			client.Timeout = 5 * time.Second
			// Upstream REALITY performs asynchronous target probes and retries their readiness after five seconds.
			if mode == "reality-vision" {
				client.Timeout = 12 * time.Second
			}
			response, e := client.Get(target.URL)
			if e != nil {
				entries, _ := logs.Drain()
				for _, entry := range entries {
					if strings.Contains(entry.Text, "REALITY") || strings.Contains(entry.Text, "handshake") {
						t.Log(entry.Text)
					}
				}
				t.Fatal(e)
			}
			n, e := io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if e != nil || n != 128<<10 {
				t.Fatalf("stream payload %d: %v", n, e)
			}
			if registry.Counters()[1][1] < 128<<10 {
				t.Fatal("TLS/Vision/XHTTP payload bypassed accounting")
			}
			registry.SetUsers([]protocol.User{})
			if _, e = client.Get(target.URL); e == nil {
				t.Fatal("revoked secured stream remained usable")
			}
		})
	}
}
