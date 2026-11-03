package main

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func activityContract(dir string, path, async map[string]any) {
	path["parameters"] = append(path["parameters"].([]any), map[string]any{"in": "header", "name": protocol.ActivityObservationsHeader, "required": false, "description": "Offer bounded boot-scoped IP observation history and actual sampling timestamps. Independent of compression and compact telemetry.", "schema": map[string]any{"type": "string", "const": protocol.ActivityObservationsFormat}})
	headers := path["responses"].(map[string]any)["101"].(map[string]any)["headers"].(map[string]any)
	headers[protocol.ActivityObservationsHeader] = map[string]any{"description": "Accepted activity observation extension; also requires the agent hello capability.", "schema": map[string]any{"type": "string", "const": protocol.ActivityObservationsFormat}}
	schema := protocol.Schema(protocol.TelemetryReport{})
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["title"] = "Authoritative telemetry snapshot"
	metrics := schema["properties"].(map[string]any)["users"].(map[string]any)["properties"].(map[string]any)
	metrics["active_ip_observations"].(map[string]any)["maxItems"] = protocol.MaxActivityObservations
	write(filepath.Join(dir, "schemas", "telemetry.schema.json"), schema)
	async["x-activity-observations"] = map[string]any{"header": protocol.ActivityObservationsHeader, "format": protocol.ActivityObservationsFormat, "capability": protocol.ActivityObservationsCapability, "maxObservations": protocol.MaxActivityObservations, "volatile": true}
	message := protocol.Schema(protocol.Message{})
	fields := message["properties"].(map[string]any)
	fields["type"] = map[string]any{"type": "string", "const": "telemetry.report"}
	fields["data"] = map[string]any{"$ref": "schemas/telemetry.schema.json"}
	async["channels"].(map[string]any)["control"].(map[string]any)["messages"].(map[string]any)["telemetry"] = map[string]any{"payload": message}
}
