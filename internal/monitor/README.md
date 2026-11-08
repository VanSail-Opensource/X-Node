# Host sampling

Optional NVIDIA probes use the shared host runner with a fixed executable path
and minimal child environment; see `docs/process-environment.md`.

`sampler.go` publishes immutable snapshots on the configured sample interval. `slow.go` bounds socket/process/GPU scans to ten seconds; `gpu.go` handles optional hardware probes. Reports reuse the last completed sample, and read failures remain explicit in its error map. No live observations are persisted.

`cadence.go` changes sampling intervals through a coalesced wakeup and one ticker/collector. Collection time does not extend the interval; missed ticks coalesce, contexts bound collection, and reports reuse the immutable latest snapshot.
