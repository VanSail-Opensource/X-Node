package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestProfilesShareCertificateManager(t *testing.T) {
	p := NewPool(t.TempDir())
	defer p.Stop()
	profile := protocol.Certificate{Config: config.CertConfig{Domain: "node.example.com", CertMode: "self"}}
	c := protocol.Config{Certificates: map[string]protocol.Certificate{"a": profile, "b": profile}}
	resolved, e := p.Prepare(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.profiles) != 1 || resolved.Certificates["a"].Config.CertFile != resolved.Certificates["b"].Config.CertFile {
		t.Fatal("same certificate duplicated")
	}
	if len(p.Status()) != 0 {
		t.Fatal("prepared profile was published before activation")
	}
	p.RetainRuntime(c, resolved)
	p.Commit(c)
	if p.Status()["a"].Expires.IsZero() {
		t.Fatal("missing certificate expiry")
	}
}

func TestPrepareRetainedUsesPersistedCertificateAndKeepsPendingMaterial(t *testing.T) {
	dir := t.TempDir()
	pool := NewPool(dir)
	defer pool.Stop()
	pending := protocol.Config{Certificates: map[string]protocol.Certificate{
		"pending": {Config: config.CertConfig{Domain: "pending.example.test", CertMode: "self"}},
	}}
	prepared, err := pool.Prepare(t.Context(), pending)
	if err != nil {
		t.Fatal(err)
	}
	configured := config.CertConfig{Domain: "accepted.example.test", CertMode: "http"}
	accepted := protocol.Config{Certificates: map[string]protocol.Certificate{"accepted": {Config: configured}}}
	cacheKey := sha256.Sum256([]byte(configured.CertMode + ":" + configured.Domain + ":" + configured.Email))
	cache := filepath.Join(dir, "acme", hex.EncodeToString(cacheKey[:]))
	if _, err := pool.PrepareRetained(t.Context(), accepted); err == nil {
		t.Fatal("fallback accepted missing local ACME material")
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("fallback created a new ACME state directory: %v", err)
	}
	// A local fixture keypair models previously persisted managed material
	// without using a CA or making network calls.
	fixture := NewManager(config.CertConfig{Domain: configured.Domain, CertMode: "self", CertDir: cache})
	if err := fixture.StartContext(t.Context(), t.Context()); err != nil {
		t.Fatal(err)
	}
	resolved, err := pool.PrepareRetained(t.Context(), accepted)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(resolved.Certificates["accepted"].Config.CertFile)
	if err != nil || !bytes.Equal(certificate, fixture.TLSCert().CertPEM) {
		t.Fatal("fallback did not use the persisted certificate", err)
	}
	if _, err := os.Stat(prepared.Certificates["pending"].Config.CertFile); err != nil {
		t.Fatal("fallback pruned the pending candidate's certificate", err)
	}
}
