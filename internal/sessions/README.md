# Logical sessions

The registry atomically reserves shared per-user TCP/UDP connections and active
IPs. Authentication labels bind credentials and inbound configuration epochs.
`registry.go` owns admission/release and current limit projections; `accounting.go`
keeps a separate native-handler lifetime and period counter after logical release.

`AcquireTracked`/`Finish` bracket actual Xray dispatch. Period changes retain
previous counters until all native handlers and sampling finish. `Quiesce` adds a
temporary admission fence and returns its release after handlers drain. Cached
`valid_until` deadlines deny new sessions immediately and close established
sessions on the next one-second control tick.

Rates use actual elapsed seconds and payload bytes. Configured normal/burst Mbps
remain a separate policy projection. Connection and source-IP snapshots are
transient. Hosted cases cover quota races, expiry, counters and quiescence.

`period_barrier.go` finishes revoked period handlers without closing renewed streams.
`period_barrier_test.go` covers late old bytes, active-period rejection and renewal continuity in hosted CI.
