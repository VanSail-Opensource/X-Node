package main

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func telemetryContract(dir string, api, async map[string]any) {
	path := api["paths"].(map[string]any)["/v1/agents/connect"].(map[string]any)["get"].(map[string]any)
	path["parameters"] = append(path["parameters"].([]any), map[string]any{"in": "header", "name": protocol.TelemetryFormatHeader, "required": false, "description": "Offer compact telemetry for this authenticated connection. The master echoes the accepted format; absence selects legacy telemetry.", "schema": map[string]any{"type": "string", "const": protocol.CompactTelemetryFormat}})
	path["responses"].(map[string]any)["101"].(map[string]any)["headers"] = map[string]any{protocol.TelemetryFormatHeader: map[string]any{"description": "Accepted telemetry format; compact also requires the agent hello capability.", "schema": map[string]any{"type": "string", "const": protocol.CompactTelemetryFormat}}}
	messages := path["x-websocket-messages"].(map[string]any)
	messages["agentToMaster"] = append(messages["agentToMaster"].([]string), "telemetry.compact")
	schema := protocol.Schema(protocol.CompactTelemetryReport{})
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["title"] = "Authoritative compact telemetry snapshot v1"
	properties := schema["properties"].(map[string]any)
	rows := properties["u"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	rows["i"].(map[string]any)["minimum"] = 1
	rows["c"].(map[string]any)["minimum"] = 0
	rows["o"].(map[string]any)["minimum"] = 0
	write(filepath.Join(dir, "schemas", "telemetry-compact.schema.json"), schema)
	agent := async["channels"].(map[string]any)["control"].(map[string]any)["messages"].(map[string]any)
	envelope := protocol.Schema(protocol.Message{})
	fields := envelope["properties"].(map[string]any)
	fields["type"] = map[string]any{"type": "string", "const": "telemetry.compact"}
	fields["data"] = map[string]any{"$ref": "schemas/telemetry-compact.schema.json"}
	envelope["required"] = append(envelope["required"].([]string), "data")
	agent["compactTelemetry"] = map[string]any{"payload": envelope}
}
