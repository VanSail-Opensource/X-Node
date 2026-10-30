# Host sampling

`sampler.go` publishes immutable snapshots on the configured sample interval. `slow.go` bounds socket/process/GPU scans to ten seconds; `gpu.go` handles optional hardware probes. Reports reuse the last completed sample, and read failures remain explicit in its error map. No live observations are persisted.
