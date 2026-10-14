# Agent orchestration

`agent.go` owns serialized desired-state and runtime activation. Utility jobs use
two bounded workers; they submit traffic captures back to the actor instead of
mutating sampling baselines concurrently.

`accounting.go` samples logical payload counters every second, retains separate
authorization accounting periods, publishes measured byte rates, and seals
durable flush barriers. Quiescing requires fenced admission and waits for native
handlers, including final bytes after admission slots were released.

`jobs.go` persists bounded mutation replay history. `job_privacy.go` excludes
session/IP scans, machine metrics and history reads from disk. Live read replay
data remains in process memory. Corrupt or unwritable history fails construction.

Hosted cases in `accounting_test.go` and `job_privacy_test.go` verify closed-stream
attribution and transient read results. Real stream tests live with the runtime.
