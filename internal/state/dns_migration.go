package state

import (
	"fmt"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Normalize both accepted and staged targets before bootstrap/configuration
// readers. This migration neither clears accounting nor writes a new state file.
func normalizeCachedDNS(data *Data) error {
	for _, target := range []**protocol.Config{&data.Config, &data.DesiredConfig} {
		if *target == nil {
			continue
		}
		config, err := (**target).NormalizeDNS()
		if err != nil {
			return fmt.Errorf("cached DNS configuration: %w", err)
		}
		*target = &config
	}
	return nil
}
