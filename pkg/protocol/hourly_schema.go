package protocol

import wire "github.com/VanSail-Opensource/X-Node/internal/protocol"

// HourlySchemas returns the negotiated hourly payload and command schemas.
func HourlySchemas() map[string]any { return wire.HourlySchemas() }
