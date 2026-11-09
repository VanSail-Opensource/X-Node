# Agent orchestration

`command_certificates.go` captures actor-owned desired profiles and runs bounded
ACME work through the same durable Jobs executor. Journal replay precedes current
revision/profile eligibility. `command_reload.go` verifies candidate identity
before scheduling material rechecks; `activation.go` verifies prepared bytes and
publishes serving evidence before auxiliary acceptance. `certificate_job_facts.go`
allowlists public partial outcomes while other uncertain payloads remain stripped.
Status/progress contain no PEM, private paths or provider responses. Hosted
certificate regressions cover replay, stale revisions, lock waits and serving
versus acquired material; see `docs/certificates.md`.

Authorization reception, IP controls and expiry publish complete committed
store views to the registry. Positive IP commands capture and recheck their
credential/period subject; expiry compares persisted deadlines before publication.
See `docs/ip-block-authorization.md` for replacement and replay constraints.

`asset_client.go` retains lazy native download transports. Redirect protection
is owned by the outer geodata HTTP client; `asset_redirect_test.go` verifies that
using the inner RoundTripper cannot bypass it. See `docs/http-redirects.md`.

Native preparation checks the environment before assets, certificates and cached
validation. `native_environment_test.go` verifies dependency-free rejection of
unsafe configuration. See `docs/process-environment.md`.

`ddns.go` shares scheduled/manual discovery and external-provider execution under
the existing DNS utility lock. Built-in `builtin:panel` skips provider creation
and DNS publication. Successful generated jobs append a durable change before
returning; failure retains the last valid discovery. Periodic reporting replays
bounded batches only on a negotiated connection, and `state_receive.go` persists
acknowledgements. Journal corruption disables generated DDNS jobs and logs a
warning while ordinary traffic/runtime startup remains available.

`agent.go` owns serialized desired-state and runtime activation. Utility jobs use
two bounded workers; they submit traffic captures back to the actor instead of
mutating sampling baselines concurrently.

Validated desired configuration is staged before binding listeners. Startup
retries that target after a previous bind failure, retaining the last applied
revision until the whole activation completes. Backoff also covers failures
after Xray starts, including firewall activation. `listener_recovery_test.go`
exercises a real occupied TCP port across restart and subsequent recovery.

`accounting.go` captures logical payload counters on the configured sample interval, retaining separate
authorization accounting periods, publishes measured byte rates, and seals
boot-scoped flush barriers. Quiescing requires fenced admission and waits for native
handlers, including final bytes after admission slots were released. New traffic remains bounded memory independently of durable credentials, commands and bans.
Capture baselines include the registry's transient counter generation. Only
successfully accepted, unchanged snapshots can be pruned. Admission-stop logs
and `agent.error` retain the redacted underlying failure for storage diagnostics.

`jobs.go` owns bounded command admission and inspection. `job_execution.go` runs
the existing workers; `job_journal.go` persists pre-execution intents and final
receipts outside the control-reader mutex. `job_bounds.go` limits serialized
receipt/history bytes while preserving exact integers. `job_privacy.go` excludes
observations and existing volatile controls from disk. `job_loader.go` and
`job_recovery.go` recover bounded legacy metadata; `job_evidence.go` preserves
private original bytes before compaction. Unverifiable history fences durable
utilities without failing ordinary agent startup. See `docs/job-journal.md`.

`job_bounds_test.go`, `job_loader_test.go`, `job_evidence_test.go`,
`job_recovery_test.go`, `job_recovery_io_test.go`, `job_execution_test.go` and
`job_execution_restart_test.go` cover limits, privacy, recovery, disk stalls,
intent fencing, partial outcomes and restart replay in hosted CI.

Hosted cases in `accounting_test.go` and `job_privacy_test.go` verify closed-stream
attribution and transient read results. Real stream tests live with the runtime.

`compatibility.go` compares individual capability requirements before adopting
new state during an unconfirmed upgrade. `compatibility_test.go` covers adding
utilities or member guards when accounting extensions are already cached.
The same first-adoption fence covers streamed country assets and domain-free
node-file certificates, so an unconfirmed binary can still restore its cached
configuration before accepting a contract its rollback binary cannot read.

The firewall guard owns local kernel observations and compressed ban durability;
its joined background tasks keep disk/kernel work off the control reader and Xray
payload paths. New report frames are gated by `master_controlled`, protecting
rolling upgrades with older masters. Typed firewall snapshot/delta commands use
the existing utility executor. Read-only firewall status never enters durable job history.
`geodata_schedule.go` owns completion-based hour intervals and bounded refresh retries; related hosted fixtures cover superseded configuration and successful/failure completion. GeoIP remains master-only.

`native_prepare.go` shares asset injection across activation and command validation. Certificate preflight uses an isolated pool and never issues ACME certificates or changes active certificate status. `Jobs.StartControl` reserves one bounded utility slot for urgent bans, traffic barriers and firewall confirmation; ordinary jobs retain two slots. Session/metrics commands no longer clone configuration and accounting journals unnecessarily.

`commands.go` dispatches protocol commands with execution deadlines; `command_connections.go` owns ephemeral connection/IP controls. `command_reload.go` waits for actor-owned activation, propagates supersession and keeps traffic acknowledgments available. `command_reload_test.go` covers queued versus completed activation. Immediate read-only `update.status` and `jobs.list` replies remain independent of occupied utility slots.

`job_result_test.go` covers failed completion writes after a persisted intent;
the uncertain outcome survives replay without repeating execution. Running IDs
are bound to command names and remain visible in recovery inspection.

Incremental activation uses `activation.go` and the exhaustive consumer planner in
`internal/protocol/changes.go`/`actions.go`. Controls can acknowledge an already
applied baseline directly; controls during pending activation retain the desired
native target and cannot report it applied prematurely. `loop.go` keeps control
and traffic handling independent of `synchronization.go`'s serialized worker.
Material rechecks remain pending across superseding controls/retries until the
latest activation succeeds, so a consumed certificate-renewal event is not lost.
Native preparation returns its actual candidate instead of compiling again.
`validation_cache.go` rechecks content hashes and retains only a validation proof,
separate from synthetic certificate material and activation candidates.
`asset_client.go` delays proxy-core creation until an actual download is needed.
See `docs/hot-reload.md` for consumer boundaries and fallback behavior.

Normal `command_reload.go` requests set only `RecheckMaterial`; the actor retains
this intent through superseding controls until successful activation. Only an
explicit typed force sets `ForceRebuild`. `activation.go` rechecks asset/certificate
material and uses the existing prepared incremental runtime path. Hosted
`activation_test.go` covers normal/forced reload counters and whitelist/firewall
updates without native rebuilding. Traffic capture/ACK and authorization paths
remain owned by the actor while activation runs in the serialized worker.

`reports.go` coalesces periodic/status/replay requests in one joined worker. Report encoding runs outside the actor. Local status uses a bounded socket query. `status.go` uses value-only state metadata and rejects a summary built across a revision change. `reporting_test.go` covers request coalescing, shutdown and ACK-driven replay.

`cadence.go` owns independent actor sampling/report tickers, reset only when master intervals change. `cadence_test.go` verifies start-to-start ticks, unchanged state and interval changes in hosted fake-time tests. The one-second maintenance ticker handles expiry, activation retries, utilities and watchdog independently. Active IP reporting is mandatory; the deprecated saved switch is ignored. `status_socket.go` exposes current non-secret state through the private `localstatus` query; reporting never writes status files.

`activity_test.go` verifies flush/sample independence with fake time. `activity.go` keeps throughput/activity sampling baselines independent of manual accounting captures, so a flush cannot consume the next configured rate sample. `accounting.go` returns queue-pressure barriers as retryable command failures without pausing admission.

`accounting_hourly.go` captures cumulative raw admission counters alongside
native traffic through one `Store.AddAccountingWithHourly` call. Baselines use
the controller's unique counter generations, so pruning and re-admitting the
same enrollment/period cannot replay or lose its first bytes. Capture advances
and controller sample pruning occur only after the store accepts independent
sample copies or records explicit presentation loss. Native validation failures
leave both baselines unchanged for retry. Accepted payload remains charged even
when a native writer later reports no handoff; credit settlement is separate.
`accounting_hourly_test.go` exercises failed capture retry and lower/equal/higher
readmission counters using real controller permits, without timer sleeps.

`automatic_leases.go` dispatches `firewall.leases.update` to the existing reserved
control executor and guard. Its bounded replay receipts remain memory-only;
`jobs.go` skips filesystem writes for this volatile command and `job_privacy.go`
filters it from later durable histories. `automatic_leases_test.go` verifies
completion even when the history path cannot be written. Credentials, ordinary
commands, desired configuration and bans retain their durable contracts.

Hourly ingress enforcement lives in `hourly_runtime.go` and `internal/hourly`.
Startup attaches the controller before publishing saved authorization. The
capability is advertised only with a healthy, private durable credit journal
whose immutable agent identity matches the ordinary state identity;
the WebSocket must independently negotiate and echo a fresh control session.
Unsupported masters cannot activate hourly identities. Existing identities and
native accounting retain their normal paths when hourly storage is unavailable.

`hourly_receive.go` applies memory-only grants and delays successful shrink ACKs
until native handoffs drain. `hourly_commands.go` uses the existing utility job
executor for durable install, seal and exact proof ACK commands. It never waits
on the reserved traffic/control executor. `hourly_publish.go` coalesces bounded
demand/progress frames and replays immutable credit proofs. Live progress records
admitted bytes; only a frozen and durably sealed proof can return unused credit.
`hourly_retire.go` seals old sessions/days after freezing their admission state;
already-admitted native delivery does not delay financial proof or refund bytes.
Disconnect alone does not authorize a refund. A damaged hourly journal disables
this feature and preserves its evidence without stopping legacy traffic.
Historical mixed traffic reports use the independently negotiated hourly
accounting receipt header, allowing ordinary accounting to drain after hourly
storage failure while live hourly admission remains disabled.
