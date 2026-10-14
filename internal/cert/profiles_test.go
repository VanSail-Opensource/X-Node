package cert

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
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
	if p.Status()["a"].Expires.IsZero() {
		t.Fatal("missing certificate expiry")
	}
}
