# Private state and traffic journals

`ddns.go` and `ddns_changes.go` own the private 1 MiB `ddns.json` journal using
the same atomic writer. Sequence, at most 1024 unacknowledged changes and 1024
latest successful job snapshots survive reconnects, restart and rollback to an
older agent rewriting `state.json`. Acknowledgement retires IDs but preserves the
latest discovery; identical values in one generation do not enqueue again.
New generations emit initial observations for changed panel bindings. Failed
discovery or journal persistence never advances the last valid address.
`ddns_test.go` covers replay, rollback isolation, unchanged values, acknowledgement
idempotency, generation changes, capacity and failed writes. No traffic accounting
fields or source-IP telemetry are added to this journal.

`store.go` atomically persists authorization, accepted configuration, bans, and
bounded private state. `traffic.go` exposes ordered immutable replay/acknowledgment.
`desired.go` stages validated activation targets before listener binding, using
the existing authorization revision. Acceptance clears the target; newer
authorization supersedes it. `desired_test.go` covers restart and control privacy.
`accounting.go` commits raw totals and period-tagged samples together and seals
barrier batches behind an outstanding report instead of replacing it.

The master must prefer `samples` for accounting-aware users, deduplicate the
agent's immutable sequence and commit before acknowledging. Missing samples on
legacy users remain supported. Old-period records survive resets and restart.
The 64 MiB bound still stops admission instead of discarding recorded traffic.

Sampling timestamps have one-second granularity; an abrupt process or power
failure can still lose bytes since the last successful sample. A quiesced barrier
is complete only when the master has committed every batch through its sequence.

`accounting_test.go` covers restart, ordered replay, stable outstanding batches,
separate periods and transactional overflow rejection.

`connection_controls.go` excludes `block_new` decisions from serialized state
while preserving live admission controls. Previously persisted decisions are
scrubbed on open. `connection_controls_test.go` covers restart, upgrade cleanup,
and preservation of credential/period/expiry fields.

`configuration.go` exposes bounded configuration copies and revision reads without cloning accounting journals for recovery commands.

`Metadata` reads revisions without copying credentials or journals. `Acknowledge` persists matching head progress before advancing; duplicate acknowledgements are write-free. `Pending` never seals new samples. `reporting_test.go` covers persistence failures and compares full-snapshot versus metadata allocations.
