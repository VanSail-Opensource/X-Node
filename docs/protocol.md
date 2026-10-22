# WebSocket protocol v1

`telegram_identity_rekey_v1` permits `users[].replaces_id`: the previous numeric
identity for a Telegram-ID replacement. It is unique within a snapshot and must
differ from the new ID. The registry retains matching credential generations,
paid-period counters and existing leases; stale mux admission still checks the
complete credential-bound identity. Masters must accept late journal samples by
their authenticated node and unchanged accounting period, never by a global
numeric alias alone. Cached replacements prevent rollback to an older agent.

`native_auxiliary_inbounds_v1` permits native `dokodemo-door` and `tunnel`
forwarding/utility listeners. These listeners retain native settings, never
receive managed accounts and are excluded from member connection/traffic
accounting. Managed user bindings and account arrays on these tags are rejected.
Masters must negotiate this capability before sending utility listeners.
Unsupported utility protocols remain validation errors. A rollback binary must
support every cached capability. Each newly introduced extension is blocked
during an unconfirmed binary upgrade, including when older extensions already
exist in the cache.

Optional capabilities `traffic_periods_v1`, `measured_user_rates`,
`authorization_expiry`, and `member_outbound_guards` identify the accounting-aware
agent. Masters must verify capabilities before supplying the corresponding
optional configuration fields. Go masters can import `pkg/protocol`.
Hello's `upgrade_pending` marks an unconfirmed binary upgrade. First adoption of
managed extensions is rejected until cached runtime activation confirms that
upgrade, preventing an older watchdog binary from dropping new state on rollback.

Accounting-aware users carry `accounting_period` and an optional RFC3339
`valid_until`. Expiry remains effective while disconnected. Traffic reports keep
their legacy totals and additionally carry `samples` with user ID, accounting
period, UTC `from`/`through`, and exact uploaded/downloaded bytes. For these users,
bill samples rather than adding both representations. Period IDs are master-owned
and must never be reused. Timestamp granularity is one second.

`users.rates[userID]` supplies measured `upload_bytes_per_second`,
`download_bytes_per_second`, and `sample_seconds`. These are payload byte rates;
`users.speed` still describes decimal Mbps policy limits, not measured throughput.

The `traffic.flush` command accepts optional `user_id`, `quiesce` and `accounting_period`.
A period-specific quiescence waits for the old native handlers without closing
renewed streams. It requires `traffic_period_barriers_v1`, a positive user ID,
and an accounting period that no longer admits traffic. The response echoes
`accounting_period`; only seal a period after its sequence is acknowledged.

`config.validate` accepts a complete remote configuration and performs the
same native preparation without listeners. It requires `config_validation_v1`
and validates node-local certificates/assets before a provider handover. Its
results and configuration stay out of durable command history.
With quiescence, block new admission first; the agent closes matching sessions and
waits for their native handlers before capture. The result contains `agent_id`,
the sealed journal `sequence`, `through`, and `quiesced`. The master must commit
reports through that sequence before settling or resetting the old period.
Outstanding batches stay immutable and queued barrier batches survive restart.

`member_outbounds` lists generated member proxy tags. Their endpoints must be
literal public IPs; the master resolves/validates hostnames before compilation
and retains TLS SNI separately. Agent checks reject private, mapped private,
reserved, scoped, and DNS-rebinding endpoints. Member socket overrides and
unvalidated chains are rejected. Managed SS-2022 supports AES-128/256 methods:
server keys stay on inbound settings and native user accounts omit `method`.

Session/IP scans and metrics/history reads are not written to utility history.
Signed installs and rollbacks reject binaries whose version metadata lacks
capabilities required by cached authorization or pending accounting journals.

The agent connects to the configured WSS URL with `Authorization: Bearer <token>` and the `x-node.v1` subprotocol. Authentication, agent enrollment and authorization are the master's responsibility. The agent never places its credential in the URL.

```json
{"v":1,"type":"state.sync","id":"snapshot-1","revision":1,"data":{"xray":{"inbounds":[]},"users":[]}}
```

The agent sends `agent.hello` before other frames on a new socket, then `state.request`. Hello identifies the persisted agent, fresh process boot ID, binary/core versions, applied revision and capabilities. WebSocket Ping/Pong frames keep the connection alive.

## State

| Master frame | Payload | Semantics |
| --- | --- | --- |
| `state.sync` | Complete remote configuration | Authoritative baseline; `users` is required even when empty |
| `config.apply` | Complete remote configuration | Replace configuration with an exact `base_revision` |
| `users.sync` | `{"users": [...]}` | Replace authorization |
| `users.delta` | `{"upsert": [...], "remove": [1]}` | Apply additions/replacements/removals |
| `user.controls` | `{"users":[{"id":1,"block_new":true}]}` | Change admission while retaining established eligible streams |

Revisions increase monotonically. A delta must name the current authorization revision as its base. Gaps trigger `state.request`; stale frames produce an error. Repeated full snapshots at the successfully applied revision are acknowledged without reapplying. The master must advance the revision for corrected configuration.

`state.accepted` acknowledges persisted authorization. `state.applied` acknowledges runtime activation. `state.failed` reports an activation failure; its authorization revocations remain effective. Readiness and synchronization are separate telemetry fields. User-only changes use runtime user managers when available. Listener/global changes may close affected sessions.

Users have a positive ID, credentials, eligible `inbound_tags`, and optional `active_ip_limit`, `connection_limit`, `speed_limit_mbps`, and `block_new`. Zero limits mean no configured user quota. `uuid` is used for protocol defaults; `credentials[tag]` supplies a native client/account object. The agent generates email/level and authenticated SOCKS/HTTP usernames. Transport identities bind credentials and inbound/configuration generations to prevent old mux sessions bypassing revocation.

## Reports

Bandwidth settings are shared per user across upload/download and all inbounds. `speed_limit_mbps` is the normal rate; `burst_speed_limit_mbps` is the hard ceiling, always enforced. Sustained throughput above normal for `speed_limit_after_seconds` (default 10) activates the normal cap. Throughput below 90% of normal for `speed_limit_reset_seconds` (default 1) restores bursts; this small hysteresis prevents oscillation at the enforced rate. Consecutive durations use one-second windows and actual elapsed time, independent of report intervals. A below-normal window resets the high-traffic streak. Omitting the burst ceiling retains the fixed normal rate. `users.speed[userID]` reports `normal_mbps`, `burst_mbps`, `active_mbps`, and `limited` (normal cap active).

```json
{"id":1,"uuid":"550e8400-e29b-41d4-a716-446655440000","inbound_tags":["vless"],"speed_limit_mbps":100,"burst_speed_limit_mbps":500,"speed_limit_after_seconds":10,"speed_limit_reset_seconds":1}
```

`telemetry.report` is an authoritative current snapshot containing agent/boot IDs, timestamp, liveness/readiness, revisions, per-user connection counts and limit status, rejection counters, machine metrics and certificate status. Missing users in its current online set have zero active sessions; the master must replace that set rather than merge indefinitely.

User source IPs are omitted by default. Request a one-time report with `users.active_ips`, or opt into periodic IP sets with `telemetry.include_active_ips: true`. Each requested record carries `user_id`, canonical `source_ip`, and its current connection count.

Per-user `users.status[userID]` reports `limited: true/false`, `reason`, and `scope`. A full active-IP quota has scope `new_ip`: existing IPs can still create streams when the connection quota allows it. `block_new` and connection quotas have scope `new_connection`. Each rejected admission also emits `admission.rejected` with `user_id`, `limited: true`, `reason` and `scope`; `source_ip` appears only when periodic IP reporting is enabled. Reasons include `ineligible`, `block_new`, `torrent_ban`, `ip_temp_block`, `blocked_port`, `connection_limit`, `active_ip_limit`, and `storage_backpressure`.

`traffic.report` contains `{id, traffic}`, with `traffic[userID] = [upload_bytes, download_bytes]`. The batch ID is stable across retries and process restarts. Deduplicate it before billing, then send:

```json
{"v":1,"type":"traffic.ack","data":{"id":"agent-id:sequence"}}
```

Only the matching pending batch is retired. Status and logs are disposable snapshots; traffic is acknowledged durable data. `logs.report` supplies timestamped entries and a dropped-entry count. Secrets are redacted before console, file forwarding and remote report serialization.

## Commands

```json
{"v":1,"type":"command","id":"operation-1","data":{"name":"connections.list","args":{"limit":100}}}
```

Commands emit `command.accepted`, optional `command.progress`, and `command.result`. Results contain `id`, `command`, `status`, optional `data/error`, and completion time. Two utility workers run concurrently. The last 128 completed results are retained across restart for request-ID deduplication; IDs must remain unique beyond this window.

| Command | Arguments |
| --- | --- |
| `connections.list` | `after`, `limit` (default 100, maximum 1000); cursor is the last returned session ID |
| `connections.close` | Session `id`, or `user_id` plus optional `inbound_tag` |
| `users.active_ips` | Optional `user_id`; omission requests current active source addresses for all users |
| `ips.control` | `source_ip`, optional `user_id`, and `drop`, `block_seconds` or `unblock` |
| `metrics.get`, `certificates.get`, `jobs.list`, `firewall.status`, `update.check` | Empty object |
| `runtime.reload` | `{force?:boolean}`; recheck material and apply incrementally; force requests recovery |
| `ddns.run` | `job_id` from the accepted configuration |
| `geodata.refresh` | Empty object; refresh then incrementally apply the verified generation |
| `speedtest` | `peer_outbound`, HTTPS `download_url`/`upload_url`, optional `max_bytes`/`timeout_seconds` |
| `firewall.apply` | `policy`, optional `dns_redirect` |
| `firewall.confirm` | `transaction_id` from `firewall.pending` or the apply result |
| `update.install` | Optional stable `version` |
| `update.rollback` | Empty object |

Cancellation uses `command.cancel` with `{id: operation-id}`. Completed operations remain queryable; cancellation cannot undo a mutation already accepted by an external provider.

IP controls target exact client source addresses, normalized so IPv4-mapped IPv6 equals IPv4. An omitted/zero `user_id` targets every user at that address. `drop: true` closes current matching logical sessions. `block_seconds: 1..604800` rejects new matching sessions until a persisted deadline; existing sessions remain unless drop is also requested. `unblock: true` clears that scoped ban. Drop-only does not create a ban.

```json
{"v":1,"type":"command","id":"ip-action-1","data":{"name":"ips.control","args":{"source_ip":"192.0.2.10","user_id":42,"drop":true,"block_seconds":600}}}
```

Firewall transactions default to 45 seconds. The master must confirm using the existing or re-established socket after testing connectivity. An independent systemd watchdog restores both live rules and persisted policy if confirmation is absent.

The native Go engine commits ordered rule/set changes as one atomic Netlink
transaction while preserving existing bans, meters, and counters. Repeating the
current transaction ID is idempotent; changing its inputs is rejected. Pending
transactions are recovered after restart. The `native_firewall_v1` capability
identifies binaries that support native policy restoration; firewall command and
policy wire formats remain unchanged.

`host_firewall_ownership_v1` additionally identifies nftables/UFW service takeover
and durable service-state rollback. A confirmed policy enables nftables, disables
and masks competing UFW enforcement, and restores original service/config state
on rollback or uninstall. A stored takeover journal prevents unsafe binary
downgrades. The privileged CI fixture covers enabled/disabled nftables and Ubuntu
24.04 UFW in marked disposable VMs.

`xtables_compat_snapshot_v1` identifies binaries that can snapshot and replay the
tables iptables-nft owns. nft cannot express their `xt match`/`xt target` rules,
so they are captured per table with the iptables front end and restored after the
native snapshot. A stored original snapshot prevents downgrades that would flush
host rules they cannot recreate.

Speedtests use a separate outbound-only Xray client and transfer HTTPS payloads through the peer. They default to three request-latency samples, at most 32 MiB download, 8 MiB upload and 60 seconds total. The transfer bound can reach 64 MiB and timeout 120 seconds. Test credentials and HTTP endpoints are supplied and managed by the master.

`torrent.detected` reports `user_id` and ban deadline. `torrent.expired` reports expiry. `block_new` controls and per-machine connection reports implement approximate global totals; no per-admission master reservation is performed.

## Operational settings

The configuration schema describes provider credentials, certificate profiles, inbound certificate references, DDNS jobs, resolver policy, firewall policy, outbound port ranges, asset hashes, telemetry, torrent policy and update policy. Operational defaults are one-second sampling, five-second reporting, five-minute DDNS refresh, ten-minute torrent bans and disabled automatic binary installation.

The agent owns verified geosite.dat domain downloads and suppresses the core's duplicate downloader. GeoIP data and source-prefix resolution belong to the master. Native domain assets stay inside the managed directory; completion-based hour intervals, retained legacy cron and download outbound selection are honored. SHA-256 hashes are supplied through `asset_hashes[file]`.

Signed handover checks compare authenticated hello `binary_sha256` and `platform`
with the official version-bound minisign manifest. This measurement identifies
a trusted enrolled agent build; it is not hardware attestation. Masters can use
`pkg/releases` to apply the exact update trust policy.

Connection-derived `block_new` controls remain in memory. The agent advertises `volatile_connection_controls_v1`; cached authorization keeps credentials, expiry and accounting periods, but never resurrects a historical global connection decision after restart.

## Firewall control v1

Agents advertise `firewall_control_v1`. A supporting master sets
`firewall.master_controlled`; older masters receive no new event frames.
`firewall.events` carries a stable `instance_id`, ordered event IDs, timestamps,
IP/rule/count evidence and live kernel status. Masters acknowledge committed IDs
with `firewall.events.ack`. Each report contains at most 256 durable events;
agents retain and resend the remainder until acknowledged. Detection never
inserts a blacklist entry.

Commands `firewall.bans.sync`, `firewall.bans.update` and `firewall.bans.get` use
the existing command executor. Every mutation requires a positive master
`version` and immutable `snapshot_id`. Snapshot chunks are ordered by `index`
and remain inactive until `final`. `sources_complete` controls authoritative
source replacement; `remove_sources` explicitly retires sources during partial
coverage. A source `reference` requires the existing matching generation.

Bans include prefix, generation, absolute `until` and refresh seconds; new commands
can reset shorter lifetimes. Retries do not extend the original deadline. IPv4
uses /32 and IPv6 /64; exemptions use exact addresses. Only a newer master
authorization can extend a ban. Expiry events retain their
generation so obsolete events cannot clear newer bans. A source-expired event
means its authorized deadline has expired.

Source inventories use `sources_only` snapshots and a separate source version.
Dynamic bans and exemptions continue to accept newer deltas while an older source
generation stages; source commits never overwrite a newer paid exemption.

## Sampled activity and master policies

`sampled_activity_v1` reports only live flows with increasing payload counters in the latest interval. Idle/open/native completion resources and traffic accounting are independent. `transit_credentials_v1` adds bounded peer credentials to each owner, scoped by source node, inbound and generation; peer hops remain metered but are absent from client connection/IP counts.

`source_geoip_firewall_v1` accepts only master-resolved prefix generations and non-REALITY listener bindings. Agents reject GeoIP downloads and routing/DNS selectors. `shared_domain_blocks_v1` adds a front-of-routing domain block policy. `geodata_interval_v1` permits completion-based `geodata.interval_hours` (0 disables, 1..8760 enables); legacy cron is retained when interval is absent.

Commands have a separate 30-second acceptance deadline. Execution is bounded to 30 seconds by default, two minutes for native validation/reload/update checks and traffic barriers, 90 seconds for speedtests, five minutes for geodata refresh/firewall preparation and ten minutes for installation or bulk range preparation. `runtime.reload` and `geodata.refresh` on agents advertising `activation_commands_v1` complete only after activation, retaining the previous runtime until native preparation succeeds. `update.status` returns the durable transaction (ID, version, previous version, status and deadline); it and `jobs.list` reply without a utility slot. `update_transaction_v1` enables reconciliation after reconnect. Confirm an upgrade only with a matching confirmed transaction plus fresh ready/synchronized telemetry at the current configuration revision. A version string alone is insufficient.

## Whitelists and fleet detection

`member_source_whitelist_v1` adds `whitelist_enabled` and exact `whitelisted_ips`
to durable user authorization. An enabled empty list denies member ingress.
Changes close affected existing ingress sessions before acknowledgment. This
check uses Xray's authenticated source address and trusted-proxy configuration,
not an untrusted request header. Independently authenticated transit credentials
bypass member IP checks on subsequent routing hops; expiry, accounting and
routing revocation still apply. `whitelist_transit_test.go` pins this separation
and delayed transit classification after a Telegram identity rekey in hosted CI.

`firewall_master_observation_v1` reports bounded IP/rule count deltas without a
node-local threshold. Event IDs remain durable and retryable until acknowledged;
masters aggregate across nodes and deduplicate retries. With probe protection
on, detections pass and only master-issued bans drop traffic. With protection
off, matching invalid/probe/closed-port traffic drops silently. Normal TCP
handshakes on open ports remain available. Source inventories follow the same
mode and never cause autonomous bans in observation mode.

`firewall.protected.sync` replaces exact volatile managed-node addresses through
the existing executor. They are excluded from detection and all blacklist banks,
including source inventories. Active user whitelist IPs join the kernel bypass
until their authorization expiry; removing one owner's exemption preserves any
other owner's active exemption. Non-Reality geolocation filtering precedes every
bypass. Protected-address commands and live IP projections are private and do
not enter durable command history. Whitelist/firewall changes update registry
and nftables state without reconstructing native Xray.
