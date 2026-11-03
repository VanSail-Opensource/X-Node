package main

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func automaticLeaseContract(dir string, api, async map[string]any) {
	schema := protocol.AutomaticLeaseSchema()
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["title"] = "Volatile exact-address automatic firewall leases"
	write(filepath.Join(dir, "schemas", "automatic-leases.schema.json"), schema)
	metadata := map[string]any{"capability": protocol.AutomaticLeaseCapability, "command": protocol.AutomaticLeaseCommand, "maximumBatch": protocol.MaxAutomaticLeaseBatch, "maximumEntries": protocol.MaxAutomaticLeases, "volatile": true, "absoluteDeadlines": true, "schema": "schemas/automatic-leases.schema.json"}
	api["x-automatic-firewall-leases"], async["x-automatic-firewall-leases"] = metadata, metadata
}
