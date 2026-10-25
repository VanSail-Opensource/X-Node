package main

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func ddnsContract(dir string, api, async map[string]any) {
	path := api["paths"].(map[string]any)["/v1/agents/connect"].(map[string]any)["get"].(map[string]any)
	path["parameters"] = append(path["parameters"].([]any), map[string]any{"in": "header", "name": protocol.DDNSChangesHeader, "required": false, "description": "Offer acknowledged DDNS changes. A master echoes the accepted format; absence preserves legacy DDNS reporting.", "schema": map[string]any{"type": "string", "const": protocol.DDNSChangesFormat}})
	path["responses"].(map[string]any)["101"].(map[string]any)["headers"].(map[string]any)[protocol.DDNSChangesHeader] = map[string]any{"description": "Accepted DDNS change format; also requires the hello capability.", "schema": map[string]any{"type": "string", "const": protocol.DDNSChangesFormat}}
	messages := path["x-websocket-messages"].(map[string]any)
	messages["agentToMaster"] = append(messages["agentToMaster"].([]string), "ddns.changes")
	schema := protocol.Schema(protocol.DDNSChanges{})
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	changes := schema["properties"].(map[string]any)["changes"].(map[string]any)
	changes["minItems"], changes["maxItems"] = 1, protocol.MaxDDNSChangesPerFrame
	changes["items"].(map[string]any)["properties"].(map[string]any)["sequence"].(map[string]any)["minimum"] = 1
	write(filepath.Join(dir, "schemas", "ddns-changes.schema.json"), schema)
	envelope := protocol.Schema(protocol.Message{})
	fields := envelope["properties"].(map[string]any)
	fields["type"] = map[string]any{"type": "string", "const": "ddns.changes"}
	fields["data"] = map[string]any{"$ref": "schemas/ddns-changes.schema.json"}
	envelope["required"] = append(envelope["required"].([]string), "data")
	async["channels"].(map[string]any)["control"].(map[string]any)["messages"].(map[string]any)["ddnsChanges"] = map[string]any{"payload": envelope}
}
