# Public protocol schemas

`main.go` generates the configuration/master-envelope schemas and OpenAPI/AsyncAPI
documents from public protocol types. `telemetry.go`, `ddns.go` and `compute.go`
extend their corresponding negotiated contracts. `traffic.go` publishes report
and barrier schemas, independent boot-stream negotiation and bounded Zstandard
framing metadata. Generated documents remain committed so hosted CI can detect
drift. Generation performs no network or database operation.

`activity.go` adds the independently negotiated bounded IP observation extension
and a full telemetry schema. Observation/loss counters remain decimal strings.

`automatic.go` publishes volatile exact-address lease arguments, maximum batch and
entry counts, capability negotiation metadata and absolute-deadline semantics.

`hourly.go` emits `hourly.schema.json`, both session-echo headers and hourly
message/credit-command metadata. Runtime shape constraints come from the shared
protocol schemas; large native sample IDs and counters remain decimal strings.
