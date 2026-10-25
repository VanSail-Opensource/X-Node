# Module

`telemetry_compact.go` defines the optional authoritative snapshot format.
`CompactTelemetry` removes default observations and repeated user keys;
`ExpandTelemetry` creates fresh internal maps and validates row identity, rates
and counters. Transport/header constants are exported through `pkg/protocol`.
`payload.go` bounds expanded message input before JSON decoding. These pure
codecs neither grant access nor change journal traffic/accounting payloads.

`firewall.go` defines configurable rules, authoritative restrictions, exact-IP
exemptions, compact source generations and versioned updates. `firewall_state.go`
defines live status. The `firewall_control_v1` capability and `master_controlled`
policy flag negotiate reports; no detector is authorized to create a blacklist.
Reports share the `MaxFirewallEventsPerFrame` limit of 256 events, and country
transfers use `GeoIPPrefixesPerChunk` to bound each staged command.

`transit.go` defines bounded master-only peer credentials on managed users. `native_policies.go` and `source_listeners.go` validate resolved source-IP firewall generations and shared domain selectors; IP geodata is never accepted by agent routing or DNS. New fields require `transit_credentials_v1`, `source_geoip_firewall_v1`, and `shared_domain_blocks_v1`; activity semantics advertise `sampled_activity_v1`.

`command_deadlines.go` defines bounded execution after acceptance, independently of the 30-second delivery deadline. Recovery inspection adds `update.status`; `activation_commands_v1` identifies reload results that wait for activation, and `update_transaction_v1` identifies durable update status support.

`runtime_reload.go` defines typed optional forced recovery; generated command
schemas reject unrecognized reload arguments. Normal reload requires
`incremental_reload_v1` for masters adopting the incremental contract.
