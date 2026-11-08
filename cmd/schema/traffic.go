package main

import (
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func trafficContract(dir string, api, async map[string]any) {
	report := protocol.Schema(protocol.TrafficReport{})
	report["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	report["title"] = "X-Node immutable traffic report"
	properties := report["properties"].(map[string]any)
	properties["stream_id"].(map[string]any)["pattern"] = "^[0-9a-f]{32}$"
	properties["hourly_samples"].(map[string]any)["maxItems"] = 8192
	properties["hourly_samples"].(map[string]any)["description"] = "Raw hourly-mode member-ingress admission deltas; excludes authenticated transit and native traffic multipliers. Independent from durable credit proofs."
	properties["dropped_hourly_samples"].(map[string]any)["description"] = "Decimal count of omitted hourly presentation samples; marks incomplete usage history without changing financial credit proofs."
	write(filepath.Join(dir, "schemas", "traffic-report.schema.json"), report)
	write(filepath.Join(dir, "schemas", "traffic-barrier.schema.json"), protocol.Schema(protocol.TrafficBarrier{}))
	framing := map[string]any{"offerHeader": protocol.ReportFramingHeader, "offerValue": protocol.ZstdReportFraming,
		"capability": protocol.ReportFramingCapability, "magicHex": "584e5a01", "decodedLength": "uint32-big-endian",
		"codec": "zstandard", "level": protocol.ReportZstdLevel, "maxDecodedBytes": protocol.MaxFrameBytes,
		"maxEncodedBytes": protocol.MaxReportFrameBytes, "permessageDeflate": false}
	streams := map[string]any{"offerHeader": protocol.TrafficStreamHeader, "offerValue": protocol.TrafficStreamFormat,
		"capability": protocol.TrafficStreamCapability, "reportSchema": "schemas/traffic-report.schema.json",
		"barrierSchema": "schemas/traffic-barrier.schema.json", "identity": "agent_id:boot_id:sequence",
		"acknowledgement": "after atomic usage, financial effects and cursor commit",
		"lossPolicy":      "settle surviving committed usage; never fabricate missing bytes or advance a cursor for lost reports"}
	api["x-report-framing"], async["x-report-framing"] = framing, framing
	api["x-traffic-streams"], async["x-traffic-streams"] = streams, streams
}
