// schema emits the transport contract from the agent's public wire types.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"path/filepath"
)

func main() {
	dir := "docs"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	schemas := protocol.Schemas()
	write(filepath.Join(dir, "schemas", "config.schema.json"), schemas["config"])
	write(filepath.Join(dir, "schemas", "master-message.schema.json"), schemas["master_message"])
	api := map[string]any{"openapi": "3.1.1", "info": map[string]any{"title": "X-Node master WebSocket contract", "version": "1.0.0", "description": "The agent initiates one WSS connection. Application operations are WebSocket frames; no REST endpoints represent them."}, "servers": []any{map[string]any{"url": "https://master.example.com"}}, "paths": map[string]any{"/v1/agents/connect": map[string]any{"get": map[string]any{"operationId": "connectAgent", "summary": "Upgrade the authenticated agent connection to WebSocket", "security": []any{map[string]any{"bearerAuth": []string{}}}, "parameters": []any{map[string]any{"in": "header", "name": "Sec-WebSocket-Protocol", "required": true, "schema": map[string]any{"const": "x-node.v1", "type": "string"}}}, "responses": map[string]any{"101": map[string]any{"description": "WebSocket connection established"}, "401": map[string]any{"description": "Invalid or missing bearer credential"}, "426": map[string]any{"description": "WebSocket upgrade required"}}, "x-websocket-messages": map[string]any{"masterToAgent": map[string]any{"$ref": "schemas/master-message.schema.json"}, "agentToMaster": []string{"agent.hello", "state.request", "state.accepted", "state.applied", "state.failed", "telemetry.report", "traffic.report", "logs.report", "command.accepted", "command.progress", "command.result", "error", "firewall.pending", "torrent.detected", "torrent.expired", "admission.rejected"}}}}}, "components": map[string]any{"securitySchemes": map[string]any{"bearerAuth": map[string]any{"type": "http", "scheme": "bearer"}}}}
	write(filepath.Join(dir, "openapi.json"), api)
	async := map[string]any{"asyncapi": "3.1.0", "info": map[string]any{"title": "X-Node control channel", "version": "1.0.0"}, "servers": map[string]any{"master": map[string]any{"host": "master.example.com", "protocol": "wss"}}, "channels": map[string]any{"control": map[string]any{"address": "/v1/agents/connect", "messages": map[string]any{"masterMessage": map[string]any{"payload": map[string]any{"$ref": "schemas/master-message.schema.json"}}, "agentMessage": map[string]any{"payload": protocol.Schema(protocol.Message{})}}}}, "operations": map[string]any{"receiveMasterState": map[string]any{"action": "receive", "channel": map[string]any{"$ref": "#/channels/control"}}, "sendAgentReports": map[string]any{"action": "send", "channel": map[string]any{"$ref": "#/channels/control"}}}}
	write(filepath.Join(dir, "asyncapi.json"), async)
}
func write(path string, value any) {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		panic(e)
	}
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(path, append(b, '\n'), 0644); e != nil {
		panic(e)
	}
	fmt.Println(path)
}
