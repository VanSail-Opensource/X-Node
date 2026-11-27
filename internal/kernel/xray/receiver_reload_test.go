package xray

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func testTLSReceiver(t *testing.T, config protocol.Config) (protocol.Config, string, func(int64) []byte) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}), 0600); err != nil {
		t.Fatal(err)
	}
	writeCertificate := func(serial int64) []byte {
		t.Helper()
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "localhost"},
			DNSNames:     []string{"localhost"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, &private.PublicKey, private)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath+".next", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(certPath+".next", certPath); err != nil {
			t.Fatal(err)
		}
		return der
	}
	config = editNative(t, config, func(root map[string]any) {
		root["inbounds"].([]any)[0].(map[string]any)["streamSettings"] = map[string]any{
			"security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}}},
		}
	})
	return config, certPath, writeCertificate
}

func dialTLSReceiverEcho(t *testing.T, port int, uuid string, cert []byte, echo net.Listener) net.Conn {
	t.Helper()
	fingerprint := sha256.Sum256(cert)
	peer := map[string]any{
		"tag": "peer", "protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": uuid, "encryption": "none"}},
		}}},
		"streamSettings": map[string]any{
			"security": "tls", "tlsSettings": map[string]any{"serverName": "localhost", "pinnedPeerCertSha256": hex.EncodeToString(fingerprint[:])},
		},
	}
	conn, err := core.Dial(t.Context(), nativeClient(t, peer), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func checkReceiverStreamEnded(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("data")); err == nil {
		_, err = io.ReadFull(conn, make([]byte, 4))
		var timeout net.Error
		if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("expected stream to end, got %v", err)
		}
	}
}

func TestTLSReceiverReloadReplacesCertificateFromSameFiles(t *testing.T) {
	config, port := testConfig(t)
	config, certPath, writeCertificate := testTLSReceiver(t, config)
	firstCertificate := writeCertificate(1)
	registry := sessions.New()
	registry.SetUsers(config.Users)
	r := New(registry)
	t.Cleanup(r.Stop)
	if err := r.Apply(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	echo := echoListener(t)
	old := dialTLSReceiverEcho(t, port, testUUID, firstCertificate, echo)
	checkEcho(t, old)
	firstInstance := r.instance
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(t.Context(), config); err == nil || r.instance != firstInstance {
		t.Fatalf("invalid replacement certificate should be refused before restart: %v", err)
	}
	checkEcho(t, old)
	checkEcho(t, dialTLSReceiverEcho(t, port, testUUID, firstCertificate, echo))

	secondCertificate := writeCertificate(2)
	if err := r.Apply(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if !r.Ready() || r.instance == firstInstance || r.Statistics().Rebuilds != 2 {
		t.Fatal("changed TLS material did not perform one full receiver reload")
	}
	checkReceiverStreamEnded(t, old)
	checkEcho(t, dialTLSReceiverEcho(t, port, testUUID, secondCertificate, echo))
	updatedInstance := r.instance
	if err := r.Apply(t.Context(), config); err != nil || r.instance != updatedInstance || r.Statistics().Rebuilds != 2 {
		t.Fatalf("unchanged TLS material should stay on the live path: %v", err)
	}
}

func TestFullReceiverReloadMovesPortAndPreflightsOccupiedEndpoint(t *testing.T) {
	config, port := testConfig(t)
	registry := sessions.New()
	registry.SetUsers(config.Users)
	r := New(registry)
	t.Cleanup(r.Stop)
	if err := r.Apply(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	echo := echoListener(t)
	old := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, old)
	firstInstance := r.instance
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	newPort := occupied.Addr().(*net.TCPAddr).Port
	updated := editNative(t, config, func(root map[string]any) {
		root["inbounds"].([]any)[0].(map[string]any)["port"] = newPort
	})
	if err := r.Apply(t.Context(), updated); err == nil || r.instance != firstInstance || !r.Ready() {
		t.Fatalf("occupied candidate port disturbed the old runtime: %v", err)
	}
	checkEcho(t, old)
	checkEcho(t, dialInboundEcho(t, port, testUUID, echo))
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply(t.Context(), updated); err != nil {
		t.Fatal(err)
	}
	if !r.Ready() || r.instance == firstInstance || r.Statistics().Rebuilds != 2 {
		t.Fatal("changed port did not perform one full receiver reload")
	}
	checkReceiverStreamEnded(t, old)
	checkEcho(t, dialInboundEcho(t, newPort, testUUID, echo))
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("old listener still accepts after full receiver reload")
	}
}

func TestFullReceiverReloadFailureRestoresCompiledCertificateAndAuthorization(t *testing.T) {
	config, port := testConfig(t)
	config, _, writeCertificate := testTLSReceiver(t, config)
	oldCertificate := writeCertificate(1)
	config.Users = append(config.Users, protocol.User{ID: 42, UUID: additionalInboundUser, InboundTags: []string{"in"}})
	registry := sessions.New()
	registry.SetUsers(config.Users)
	r := New(registry)
	t.Cleanup(r.Stop)
	if err := r.Apply(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	echo := echoListener(t)
	checkEcho(t, dialTLSReceiverEcho(t, port, additionalInboundUser, oldCertificate, echo))
	firstInstance := r.instance
	newCertificate := writeCertificate(2)
	updated := editNative(t, config, func(root map[string]any) {
		stream := root["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
		// Native parsing accepts the two integers, but the TCP listener
		// rejects opposing keepalive signs during same-endpoint activation.
		stream["sockopt"] = map[string]any{"tcpKeepAliveIdle": -1, "tcpKeepAliveInterval": 1}
	})
	updated.Users = updated.Users[:1]
	registry.SetUsers(updated.Users)
	if err := r.Apply(t.Context(), updated); err == nil || r.instance == firstInstance || !r.Ready() {
		t.Fatalf("failed activation did not restore the previous receiver: %v", err)
	}
	recovered := dialTLSReceiverEcho(t, port, testUUID, oldCertificate, echo)
	checkEcho(t, recovered)
	checkReceiverStreamEnded(t, dialTLSReceiverEcho(t, port, additionalInboundUser, oldCertificate, echo))
	checkReceiverStreamEnded(t, dialTLSReceiverEcho(t, port, testUUID, newCertificate, echo))
	restoredInstance := r.instance
	prepared, err := r.Prepare(updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyPreparedContext(t.Context(), t.Context(), prepared, false); err == nil || r.instance != restoredInstance {
		t.Fatalf("automatic retry should not restart for the same failed cutover: %v", err)
	}
	checkEcho(t, recovered)
}
