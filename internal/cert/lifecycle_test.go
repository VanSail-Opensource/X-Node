package cert

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func lifecycleConfig(domain string) protocol.Config {
	return protocol.Config{Certificates: map[string]protocol.Certificate{"tls": {Config: config.CertConfig{Domain: domain, CertMode: "http"}}}}
}

func TestCertificateServingStatusUsesPreparedMaterialAfterManagerRenewal(t *testing.T) {
	p := NewPool(t.TempDir())
	defer p.Stop()
	c := lifecycleConfig("node.example")
	p.Declare(c, 7)
	certA, keyA := generateSelfSignedPair(t, "node.example")
	certB, keyB := generateSelfSignedPair(t, "node.example")
	p.acquireFn = func(_, _ context.Context, m *Manager, _ string) error { m.storePEM(certA, keyA); return nil }
	args := protocol.CertificateRunArgs{ProfileID: "tls", Action: "issue", ExpectedRevision: 7}
	candidate, err := p.Acquire(context.Background(), context.Background(), c, args, "certificate-operation")
	if err != nil {
		t.Fatal(err)
	}
	status := p.Status()["tls"]
	if status.Active || status.Fingerprint != "" || status.AcquiredFingerprint != candidate.Fingerprint || status.CommandID != "certificate-operation" {
		t.Fatal("acquisition was reported as serving", status)
	}
	resolved, err := p.PrepareContext(context.Background(), context.Background(), c, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	_, profileKey := profileSettings(c, c.Certificates["tls"])
	p.mu.Lock()
	entry := p.profiles[profileKey]
	p.mu.Unlock()
	entry.manager.storePEM(certB, keyB)
	newMaterial, _ := describeMaterial(certB)
	p.acquired(profileKey, newMaterial)
	p.RetainRuntime(c, resolved)
	p.Failed(candidate, "CERTIFICATE_ACTIVATION_FAILED") // A later firewall/state step failed.
	status = p.Status()["tls"]
	if !status.Active || status.Fingerprint != candidate.Fingerprint || status.AcquiredFingerprint != newMaterial.Fingerprint || status.Phase != "failed" {
		t.Fatal("serving evidence followed mutable manager bytes", status)
	}
	if !p.ServingMatches(candidate) {
		t.Fatal("prepared serving fingerprint lost")
	}
	result := p.Result(candidate, "issue", true)
	if !result.Applied || result.Fingerprint != candidate.Fingerprint {
		t.Fatal("partial activation facts lost", result)
	}
}

func TestFailedDesiredCertificateRemainsVisibleWithoutPrivatePaths(t *testing.T) {
	p := NewPool(t.TempDir())
	defer p.Stop()
	secretPath := "/private/unreadable/certificate.pem"
	c := protocol.Config{Certificates: map[string]protocol.Certificate{"failed": {Config: config.CertConfig{CertMode: "file", CertFile: secretPath, KeyFile: "/private/key.pem"}}}}
	p.Declare(c, 9)
	if _, err := p.Prepare(context.Background(), c); err == nil {
		t.Fatal("missing file accepted")
	}
	status := p.Status()["failed"]
	if status.Active || status.Phase != "failed" || status.ErrorCode != "CERTIFICATE_PREPARATION_FAILED" || status.Revision != 9 {
		t.Fatal("failed profile disappeared", status)
	}
	raw, _ := json.Marshal(p.Status())
	if strings.Contains(string(raw), "/private/") {
		t.Fatal("private material path leaked", string(raw))
	}
}

func TestCertificateOperationFailurePreservesOldMaterialAndSanitizesError(t *testing.T) {
	p := NewPool(t.TempDir())
	defer p.Stop()
	c := lifecycleConfig("node.example")
	p.Declare(c, 1)
	certificate, key := generateSelfSignedPair(t, "node.example")
	p.acquireFn = func(_, _ context.Context, m *Manager, _ string) error { m.storePEM(certificate, key); return nil }
	args := protocol.CertificateRunArgs{ProfileID: "tls", Action: "issue", ExpectedRevision: 1}
	first, err := p.Acquire(context.Background(), context.Background(), c, args, "first")
	if err != nil {
		t.Fatal(err)
	}
	p.acquireFn = func(_, _ context.Context, _ *Manager, _ string) error {
		return errors.New("provider token=must-not-leak")
	}
	args.Action = "renew"
	if _, err = p.Acquire(context.Background(), context.Background(), c, args, "renew"); err == nil || err.Error() != "CERTIFICATE_RENEW_FAILED" {
		t.Fatal("provider error escaped", err)
	}
	p.mu.Lock()
	entry := p.profiles[first.Key]
	p.mu.Unlock()
	material, _ := describeMaterial(entry.manager.TLSCert().CertPEM)
	if material.Fingerprint != first.Fingerprint {
		t.Fatal("failed renewal erased previous PEM")
	}
}
