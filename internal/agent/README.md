# Agent orchestration

`agent.go` owns serialized desired-state and runtime activation. Utility jobs use
two bounded workers; they submit traffic captures back to the actor instead of
mutating sampling baselines concurrently.

Validated desired configuration is staged before binding listeners. Startup
retries that target after a previous bind failure, retaining the last applied
revision until the whole activation completes. Backoff also covers failures
after Xray starts, including firewall activation. `listener_recovery_test.go`
exercises a real occupied TCP port across restart and subsequent recovery.

`accounting.go` samples logical payload counters every second, retains separate
authorization accounting periods, publishes measured byte rates, and seals
durable flush barriers. Quiescing requires fenced admission and waits for native
handlers, including final bytes after admission slots were released.

`jobs.go` persists bounded mutation replay history. `job_privacy.go` excludes
session/IP scans, machine metrics and history reads from disk. Live read replay
data remains in process memory. Corrupt or unwritable history fails construction.

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
the existing utility executor. Read-only firewall status never enters job history.
`geodata_schedule.go` owns completion-based hour intervals and bounded refresh retries; related hosted fixtures cover superseded configuration and successful/failure completion. GeoIP remains master-only.

`native_prepare.go` shares asset injection across activation and command validation. Certificate preflight uses an isolated pool and never issues ACME certificates or changes active certificate status. `Jobs.StartControl` reserves one bounded utility slot for urgent bans, traffic barriers and firewall confirmation; ordinary jobs retain two slots. Session/metrics commands no longer clone configuration and accounting journals unnecessarily.

`commands.go` dispatches protocol commands with execution deadlines; `command_connections.go` owns ephemeral connection/IP controls. `command_reload.go` waits for actor-owned activation, propagates supersession and keeps traffic acknowledgments available. `command_reload_test.go` covers queued versus completed activation. Immediate read-only `update.status` and `jobs.list` replies remain independent of occupied utility slots.

`job_result_test.go` covers failed result-journal writes: completed mutations become uncertain and their in-process replay retains that outcome without repeating execution. Running IDs are bound to command names and remain visible in recovery inspection.

Incremental activation uses `activation.go` and the exhaustive consumer planner in
`internal/protocol/changes.go`/`actions.go`. Controls can acknowledge an already
applied baseline directly; controls during pending activation retain the desired
native target and cannot report it applied prematurely. `loop.go` keeps control
and traffic handling independent of `synchronization.go`'s serialized worker.
Native preparation returns its actual candidate instead of compiling again.
`validation_cache.go` rechecks content hashes and retains only a validation proof,
separate from synthetic certificate material and activation candidates.
`asset_client.go` delays proxy-core creation until an actual download is needed.
See `docs/hot-reload.md` for consumer boundaries and fallback behavior.
