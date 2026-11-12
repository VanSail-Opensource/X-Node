# Module

`hourly.go`, `hourly_credit.go` and their validation helpers define optional
account-wide ingress grants, raw admission samples and durable financial credit
obligations. `schema_hourly.go` augments reflected types with hourly user paid
boundaries, frame-item limits and typed credit arguments; `schema.go` preserves
signed and unsigned integer string tags. `hourly_wire_test.go`,
`hourly_validation_test.go` and `hourly_credit_validation_test.go` cover exact
large integers, conditional user fields, command isolation/timeouts, malformed
grants, duplicate batches and conserved normal/recovery proofs. Public details
live in `docs/hourly-account-limits.md`; generated schema documents remain derived.

`native_xhttp.go` checks effective XHTTP HTTP/2 settings before certificates or
listeners are prepared. It mirrors the pinned Xray v26.10.31 alias precedence
and single `extra` replacement, including effective `downloadSettings`, without
calling builders or reading node-local TLS files. HTTP/2 types come from Go's
`net/http.HTTP2Config`. Protocol fixtures compare normalization with the actual
upstream typed builder and cover ignored fields and certificate placeholders.
Known HTTP/2 field types are checked wherever configured, including inactive
transport settings; unknown fields retain the upstream JSON behavior.
Effective download streams must also contain an address, nonzero port and an
XHTTP transport: the pinned native builder accepts incomplete download settings
that would later panic in its dialer. Builder-backed fixtures reject those
shapes before listeners change, preserving native method/alias/extra precedence.

Member outbounds apply their literal-public-address and owned-peer socket rules
to every effective XHTTP download stream. Case-insensitive native field names
cannot bypass socket or local-file restrictions. Public endpoint validation
shares the special-purpose IPv4/IPv6 exclusions used by automatic firewall
leases; deprecated site-local IPv6 and non-public IPv6 allocation space are
never treated as public proxy destinations.

`user_identity.go` shares credential/accounting identity equality and validates
existing `replaces_id` moves against the original authorization snapshots.
Historical hints with no old subject grant no new transfer proof and do not
block later renewal or credential rotation. Occupied targets, retained sources
and changed source identities are rejected. `user_identity_test.go` and
`user_replacements_test.go` cover mutable controls, malformed relations and
the panel's persistent alias metadata.

`ip_blocks.go` remaps exact user-scoped restrictions from original records,
preserving the latest colliding expiry, global scope and input immutability.
`ip_blocks_test.go` covers scope isolation, IPv6, collisions and non-cascading
remapping. These helpers add no wire fields or account-relinking interface and
never rewrite historical traffic or financial evidence.

`xray_environment.go` rejects unreviewed process variables before native
preparation through `ValidateNativePolicies`; `xray_environment_test.go` covers
unsafe names, malformed values and supported options. This policy is shared by
the public validator and activation; see `docs/process-environment.md`.

`open_connections_v1` adds optional total open client counts independently of
sampled `Connections`. Compact field `o` preserves idle-only rows and empty
snapshots clear totals. The capability is exported for master availability gates.
The independent `X-XNode-Open-Connections: v1` handshake must also be accepted
before sending these fields to a strict master.

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

## Negotiated compressed reports

`report_frame.go` exposes `report_zstd_l6_v1` and `X-XNode-Reports: zstd-l6-v1`.
A master echoes this offer before an updated agent uses binary report frames.
The first four bytes are 58 4e 5a 01 (XNZ and binary version 1), followed by a
four-byte big-endian decoded JSON length, then independent Zstandard data with
checksum. The JSON envelope and payload schemas remain unchanged. Controls,
commands, acknowledgements and agent.hello remain text frames. Never combine
binary report framing with WebSocket permessage-deflate. Legacy peers retain
bounded text/deflate decoding.

Level 6 uses EncoderLevelFromZstd(6), one reused encoder worker, a 1 MiB window
and low-memory operation. Decoders use one worker, enforce both the declared
length and the 16 MiB decoded cap, and bound compressed input separately. Idle
scratch buffers retain at most 512 KiB; larger buffers are disposable. These
codecs never touch the filesystem. `report_frame_test.go` covers malformed sizes,
checksums, expansion bounds and retained memory; its hosted benchmark measures
round trips over 10,000 synthetic observations.

`traffic_stream.go` validates separate legacy and boot-scoped report IDs. `accounting.go` carries stream IDs, loss observations and dual-stream flush barriers. `traffic_stream_test.go` rejects relabeling, noncanonical sequences and malformed process identities. Public report/barrier schemas and negotiation metadata are generated by `cmd/schema/traffic.go`.

`activity.go` defines independently negotiated sampled timestamps and bounded
boot-scoped IP history. `activity_validation.go` rejects missing sample times,
duplicates, invalid addresses, zero counters and future observations relative to
their sample. Full and compact formats retain the same observations and exact
decimal-string counters, covered by `activity_test.go`. `schema.go` respects
unsigned integer JSON string encoding; `cmd/schema/activity.go` publishes both
the full report schema and activity negotiation metadata.

`automatic_leases.go` publishes `volatile_firewall_leases_v1`, the bounded
`firewall.leases.update` command and exact generation/deadline acknowledgments.
`AutomaticLeaseAddress` shares pre-parsed public-address exclusions with masters.
Epochs and canonical exact IPs validate before mutation; generations are decimal
strings and batches contain at most 256 unique addresses. Expired in-flight
grants are harmless no-ops. `automatic_leases_test.go` protects precision, public
address scope, conflict inputs and capacity bounds.
