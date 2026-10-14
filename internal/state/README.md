# Private state and traffic journals

`store.go` atomically persists authorization, accepted configuration, bans, and
bounded private state. `traffic.go` exposes ordered immutable replay/acknowledgment.
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
