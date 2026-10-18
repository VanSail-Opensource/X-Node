package cert

import (
	"context"
	"errors"
	"os"

	"github.com/VanSail-Opensource/X-Node/internal/config"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// ValidateProfiles reads real local/inline material but never starts ACME or DNS
// issuance. Temporary certificates stand in for material obtained on activation.
func ValidateProfiles(ctx context.Context, c protocol.Config, visit func(protocol.Config) error) error {
	validation := protocol.Clone(c)
	for id, spec := range validation.Certificates {
		cfg, _ := profileSettings(c, spec)
		switch NewManager(cfg).resolveMode() {
		case "file", "content":
		case "http", "dns", "self":
			spec.Provider = ""
			spec.Config = config.CertConfig{Domain: cfg.Domain, CertMode: "self"}
			validation.Certificates[id] = spec
		default:
			return errors.New("invalid managed certificate mode")
		}
	}
	dir, err := os.MkdirTemp("", "xnode-certificate-validation-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	pool := NewPool(dir)
	defer pool.Stop()
	resolved, err := pool.Prepare(ctx, validation)
	if err != nil {
		return err
	}
	return visit(resolved)
}
