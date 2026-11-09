package main

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func certificateContract(dir string, api, async map[string]any) {
	status := protocol.Schema(map[string]protocol.CertificateStatus{})
	status["maxProperties"] = 2 * protocol.MaxCertificateProfiles
	statusFields := status["additionalProperties"].(map[string]any)["properties"].(map[string]any)
	statusFields["phase"] = map[string]any{"type": "string", "enum": []string{"issuing", "renewing", "applying", "idle", "failed"}}
	statusFields["sans"].(map[string]any)["maxItems"] = 128
	progress := protocol.Schema(protocol.CertificateRunProgress{})
	progress["properties"].(map[string]any)["phase"] = map[string]any{"type": "string", "enum": []string{"issuing", "renewing", "applying", "idle", "failed"}}
	result := protocol.Schema(protocol.CertificateRunResult{})
	for name, schema := range map[string]map[string]any{"certificate-status": status, "certificate-progress": progress, "certificate-result": result} {
		schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
		write(filepath.Join(dir, "schemas", name+".schema.json"), schema)
	}
	path := api["paths"].(map[string]any)["/v1/agents/connect"].(map[string]any)["get"].(map[string]any)
	path["x-certificate-lifecycle"] = map[string]any{"capability": protocol.CertificateLifecycleCapability, "command": protocol.CertificateRunCommand, "timeoutSeconds": 300, "status": map[string]any{"$ref": "schemas/certificate-status.schema.json"}, "progress": map[string]any{"$ref": "schemas/certificate-progress.schema.json"}, "result": map[string]any{"$ref": "schemas/certificate-result.schema.json"}}
	envelope := protocol.Schema(protocol.Message{})
	fields := envelope["properties"].(map[string]any)
	fields["type"] = map[string]any{"type": "string", "const": "command.progress"}
	fields["data"] = map[string]any{"$ref": "schemas/certificate-progress.schema.json"}
	async["channels"].(map[string]any)["control"].(map[string]any)["messages"].(map[string]any)["certificateProgress"] = map[string]any{"payload": envelope}
}
