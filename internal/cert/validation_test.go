package cert

import (
	"context"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestValidationDoesNotIssueAcmeOrPublishActiveProfiles(t *testing.T) {
	c := protocol.Config{Certificates: map[string]protocol.Certificate{"acme": {Config: config.CertConfig{Domain: "validation.invalid", CertMode: "http", AutoTLS: true}}}}
	if err := ValidateProfiles(context.Background(), c, func(resolved protocol.Config) error {
		if resolved.Certificates["acme"].Config.CertFile == "" {
			t.Fatal("native validation has no local material")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
