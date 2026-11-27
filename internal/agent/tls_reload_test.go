package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestWireReloadRotatesTLS(t *testing.T) {
	a, c := activationFixture(t)
	var native struct{ Inbounds []struct{ Port int } }
	if err := json.Unmarshal(c.Xray, &native); err != nil || len(native.Inbounds) != 1 {
		t.Fatalf("invalid listener fixture: %v", err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(native.Inbounds[0].Port))
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600); err != nil {
		t.Fatal(err)
	}
	rotate := func(serial int64) *x509.Certificate {
		t.Helper()
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(serial), DNSNames: []string{"localhost"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certFile+".next", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(certFile+".next", certFile); err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	verifyServing := func(want *x509.Certificate) {
		t.Helper()
		roots := x509.NewCertPool()
		roots.AddCert(want)
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{ServerName: "localhost", RootCAs: roots})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		got := conn.ConnectionState().PeerCertificates[0].SerialNumber
		if got.Cmp(want.SerialNumber) != 0 {
			t.Fatalf("listener presents certificate serial %v, want %v", got, want.SerialNumber)
		}
	}
	c.Certificates = map[string]protocol.Certificate{"file": {Config: config.CertConfig{Domain: "localhost", CertMode: "file", CertFile: certFile, KeyFile: keyFile}}}
	c.InboundCertificates = map[string]string{"paid": "file"}
	first := rotate(101)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	a.Client.Incoming <- protocol.New("state.sync", "initial", 1, c)
	await(t, func() bool { return a.Runtime.Ready() && a.Store.Metadata().ConfigRevision == 1 && !a.applying.Load() })
	verifyServing(first)
	originalFingerprint := a.Certificates.Status()["file"].Fingerprint
	before := a.Runtime.Statistics()
	reload := func(id string, args map[string]bool) {
		t.Helper()
		a.Client.Incoming <- protocol.New("command", id, 0, map[string]any{"name": "runtime.reload", "args": args})
		var result JobResult
		await(t, func() bool {
			for _, job := range a.Jobs.Snapshot() {
				if job.ID == id && job.Status != "running" {
					result = job
					return true
				}
			}
			return false
		})
		if result.Status != "completed" {
			t.Fatalf("runtime.reload %s: %s (%s)", id, result.Status, result.Error)
		}
	}
	second := rotate(202)
	reload("rotate-file", map[string]bool{})
	verifyServing(second)
	status := a.Certificates.Status()["file"]
	if !status.Active || status.Fingerprint == "" || status.Fingerprint == originalFingerprint || status.Fingerprint != status.AcquiredFingerprint {
		t.Fatalf("status did not record the newly serving material: %+v", status)
	}
	after := a.Runtime.Statistics()
	if after.Rebuilds != before.Rebuilds+1 || !a.Runtime.Ready() {
		t.Fatalf("changed material did not trigger exactly one reconstruction: %+v", after)
	}
	reload("unchanged-file", map[string]bool{"force": true})
	verifyServing(second)
	if unchanged := a.Runtime.Statistics(); unchanged.Rebuilds != after.Rebuilds || unchanged.LiveApplies != after.LiveApplies+1 {
		t.Fatalf("reload of unchanged certificate did not stay live: %+v", unchanged)
	}
}
