package main

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func hourlyContract(dir string, api, async map[string]any) {
	bundle := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "Shared hourly ingress and durable credit contracts", "$defs": protocol.HourlySchemas()}
	write(filepath.Join(dir, "schemas", "hourly.schema.json"), bundle)
	path := api["paths"].(map[string]any)["/v1/agents/connect"].(map[string]any)["get"].(map[string]any)
	response := path["responses"].(map[string]any)["101"].(map[string]any)["headers"].(map[string]any)
	headerSchemas := map[string]any{protocol.HourlyHeader: map[string]any{"type": "string", "const": protocol.HourlyFormat}, protocol.HourlySessionHeader: map[string]any{"type": "string", "pattern": "^[0-9a-f]{32}$"}}
	for _, name := range []string{protocol.HourlyHeader, protocol.HourlySessionHeader} {
		schema := headerSchemas[name]
		path["parameters"] = append(path["parameters"].([]any), map[string]any{"in": "header", "name": name, "required": false, "description": "Offer hourly enforcement only when operational; the master must echo both values exactly and check the hello capability.", "schema": schema})
		response[name] = map[string]any{"description": "Exact accepted hourly offer; no legacy fallback grants hourly payload.", "schema": schema}
	}
	messages := path["x-websocket-messages"].(map[string]any)
	messages["agentToMaster"] = append(messages["agentToMaster"].([]string), "hourly.demand", "hourly.grant.ack", "hourly.grant.acks", "hourly.credit.proofs")
	for name, key := range map[string]string{"hourly.demand": "demand", "hourly.grant.ack": "grant_ack", "hourly.grant.acks": "grant_acks", "hourly.credit.proofs": "credit_proofs"} {
		envelope := protocol.Schema(protocol.Message{})
		fields := envelope["properties"].(map[string]any)
		fields["type"], fields["v"] = map[string]any{"const": name}, map[string]any{"const": protocol.Version}
		fields["data"] = map[string]any{"$ref": "schemas/hourly.schema.json#/$defs/" + key}
		envelope["required"] = []string{"v", "type", "data"}
		async["channels"].(map[string]any)["control"].(map[string]any)["messages"].(map[string]any)[name] = map[string]any{"payload": envelope}
	}
	metadata := map[string]any{"capability": protocol.HourlyCapability, "offerHeader": protocol.HourlyHeader, "offerValue": protocol.HourlyFormat, "sessionHeader": protocol.HourlySessionHeader, "exactSessionEcho": true, "maxFrameBytes": protocol.MaxHourlyFrameBytes, "maxItems": protocol.MaxHourlyItems, "maxGrantLifetimeMilliseconds": protocol.MaxHourlyLifetimeMillis, "maxAggregateBurstBytes": protocol.MaxHourlyBurstBytes, "schema": "schemas/hourly.schema.json", "commands": []string{protocol.HourlyCreditInstallCommand, protocol.HourlyCreditSealCommand, protocol.HourlyCreditAckCommand}, "failurePolicy": "pause hourly ingress; never restore grants or unused-credit proofs on disconnect"}
	api["x-hourly-account-limits"], async["x-hourly-account-limits"] = metadata, metadata
}
