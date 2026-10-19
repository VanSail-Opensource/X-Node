package cert

import (
	"context"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestCandidateCleanupRetainsRuntimeAfterPartialActivation(t *testing.T) {
	p := NewPool(t.TempDir())
	defer p.Stop()
	prepare := func(domain string) (protocol.Config, string) {
		t.Helper()
		c := protocol.Config{Certificates: map[string]protocol.Certificate{"tls": {Config: config.CertConfig{Domain: domain, CertMode: "self"}}}}
		resolved, err := p.Prepare(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		return c, resolved.Certificates["tls"].Config.CertFile
	}
	active, activeFile := prepare("active.example")
	p.RetainRuntime(active)
	p.Commit(active)
	running, runningFile := prepare("running.example")
	p.RetainRuntime(running) // Runtime applied, but a later durable write failed.
	_, discardedFile := prepare("failed.example")
	_, candidateFile := prepare("candidate.example")
	for _, path := range []string{activeFile, runningFile, candidateFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("cleanup removed a serving or rollback dependency", err)
		}
	}
	if _, err := os.Stat(discardedFile); !os.IsNotExist(err) {
		t.Fatal("abandoned certificate material survived", err)
	}
	if len(p.profiles) != 3 {
		t.Fatal("failed certificate managers accumulated", len(p.profiles))
	}
}
