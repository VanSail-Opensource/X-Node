# Host sampling

Optional NVIDIA probes use the shared host runner with a fixed executable path
and minimal child environment; see `docs/process-environment.md`.

`sampler.go` publishes immutable snapshots on the configured sample interval. `slow.go` bounds socket/process/GPU scans to ten seconds; `gpu.go` handles optional hardware probes. Reports reuse the last completed sample, and read failures remain explicit in its error map. No live observations are persisted.

`cadence.go` changes sampling intervals through a coalesced wakeup and one ticker/collector. Collection time does not extend the interval; missed ticks coalesce, contexts bound collection, and reports reuse the immutable latest snapshot.

Linux TCP and UDP figures count IPv4 and IPv6 socket-table rows in the
agent's network namespace, not Unix-domain sockets or process owners. The
counter includes listeners and TCP states such as TIME-WAIT, reads the tables
without scanning process descriptors, and reports required table failures as
unavailable. IPv6 tables are optional when disabled. Member connection counts
are sampled separately. Go heap and completed-GC statistics do not require an
additional stop-the-world sample.
