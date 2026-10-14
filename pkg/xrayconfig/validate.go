// Package xrayconfig exposes the agent's native renderer without starting listeners.
package xrayconfig

import (
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/pkg/protocol"
)

// Validate checks managed accounts and the pinned native core configuration.
// Node-local certificate and geodata files must be available when referenced.
func Validate(config protocol.Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	_, err := xray.Prepare(config)
	return err
}
