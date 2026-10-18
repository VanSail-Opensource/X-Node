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

The firewall guard owns local kernel observations and compressed ban durability;
its joined background tasks keep disk/kernel work off the control reader and Xray
payload paths. New report frames are gated by `master_controlled`, protecting
rolling upgrades with older masters. Typed firewall snapshot/delta commands use
the existing utility executor. Read-only firewall status never enters job history.
`geodata_schedule.go` owns completion-based hour intervals and bounded refresh retries; related hosted fixtures cover superseded configuration and successful/failure completion. GeoIP remains master-only.

`native_prepare.go` shares asset injection across activation and command validation. Certificate preflight uses an isolated pool and never issues ACME certificates or changes active certificate status. `Jobs.StartControl` reserves one bounded utility slot for urgent bans, traffic barriers and firewall confirmation; ordinary jobs retain two slots. Session/metrics commands no longer clone configuration and accounting journals unnecessarily.
