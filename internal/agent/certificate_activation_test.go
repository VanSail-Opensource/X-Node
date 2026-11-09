package agent

import (
	"context"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestCertificateActivationUsesDesiredSnapshotAndRejectsStaleRevision(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Authorize([]protocol.User{}, 7); err != nil {
		t.Fatal(err)
	}
	old := protocol.Config{Certificates: map[string]protocol.Certificate{"tls": {Config: config.CertConfig{Domain: "old.example", CertMode: "http"}}}}
	if err = store.Accept(old, 7); err != nil {
		t.Fatal(err)
	}
	desired := protocol.Clone(old)
	desired.Certificates["tls"] = protocol.Certificate{Config: config.CertConfig{Domain: "new.example", CertMode: "http"}}
	pool := cert.NewPool(t.TempDir())
	defer pool.Stop()
	pool.Declare(desired, 7)
	a := &Agent{Store: store, Certificates: pool, desired: desired, hasDesired: true, apply: make(chan applyJob, 1)}
	key, _ := cert.ProfileKey(desired, "tls")
	candidate := cert.Candidate{ProfileID: "tls", Key: key, Fingerprint: "new-material"}
	done := make(chan error, 1)
	a.handleReloadRequest(reloadRequest{ID: "issue", Context: context.Background(), ExpectedRevision: 7, Certificate: &candidate, Done: done})
	job := <-a.apply
	defer a.cancelApply()
	if job.Config.Certificates["tls"].Config.Domain != "new.example" || job.Certificate != &candidate || !job.RecheckMaterial {
		t.Fatal("activation used accepted old config", job)
	}
	select {
	case <-done:
		t.Fatal("queued activation was reported complete")
	default:
	}
	stale := make(chan error, 1)
	a.handleReloadRequest(reloadRequest{ID: "stale", Context: context.Background(), ExpectedRevision: 6, Certificate: &candidate, Done: stale})
	if err := <-stale; err == nil {
		t.Fatal("stale certificate candidate admitted")
	}
	select {
	case <-a.apply:
		t.Fatal("stale candidate entered apply queue")
	default:
	}
}
