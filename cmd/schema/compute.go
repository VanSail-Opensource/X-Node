package main

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func computeContract(api, async map[string]any) {
	path := api["paths"].(map[string]any)["/v1/agents/connect"].(map[string]any)["get"].(map[string]any)
	path["parameters"] = append(path["parameters"].([]any), map[string]any{"in": "header", "name": protocol.ComputePoolHeader, "required": false, "description": "Offer bounded numerical compute. Both the response header and hello capability are required.", "schema": map[string]any{"type": "string", "const": protocol.ComputePoolFormat}})
	path["responses"].(map[string]any)["101"].(map[string]any)["headers"].(map[string]any)[protocol.ComputePoolHeader] = map[string]any{"description": "Accepted compute pool version.", "schema": map[string]any{"type": "string", "const": protocol.ComputePoolFormat}}
	messages := path["x-websocket-messages"].(map[string]any)
	messages["agentToMaster"] = append(messages["agentToMaster"].([]string), "compute.claim", "compute.heartbeat", "compute.result", "compute.cancel")
	for name, value := range map[string]any{"compute.claim": protocol.ComputeSignal{}, "compute.heartbeat": protocol.ComputeSignal{}, "compute.result": protocol.ComputeChunk{}, "compute.cancel": protocol.ComputeSignal{}} {
		envelope := protocol.Schema(protocol.Message{})
		fields := envelope["properties"].(map[string]any)
		fields["type"] = map[string]any{"const": name}
		fields["data"] = protocol.Schema(value)
		envelope["required"] = []string{"v", "type", "data"}
		async["channels"].(map[string]any)["control"].(map[string]any)["messages"].(map[string]any)[name] = map[string]any{"payload": envelope}
	}
}
