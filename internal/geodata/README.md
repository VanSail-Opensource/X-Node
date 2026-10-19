# Domain geodata

`assets.go` stages only verified geosite.dat domain assets and retains the last valid immutable generation. GeoIP downloads and selector resolution belong to the master. `Policy.interval_hours` selects a completion-based whole-hour interval (0 disables); absent values preserve legacy cron or disabled scheduling. `agent/geodata_schedule.go` serializes refreshes, retains deadlines across unrelated state applies, retries failures after 1/5/15 minutes and schedules the next regular run after completion. Existing asset hash/size/atomic activation constraints remain in force. Hosted coverage is in `assets_test.go` and `schedule_test.go`.

`Prepare` stages a candidate without publishing it; `Activate` runs only after runtime validation/application, retaining the prior generation across repeated applies. `agent/native_prepare.go` injects the asset path before both activation and command validation without relying on the service's ambient asset setting.

Failed candidates are bounded to the active, previous and latest prepared generation. A native geosite lookup missing from cached data triggers one verified refresh, while repeated failed candidates wait for paced/manual refresh instead of downloading on every retry.

`cleanup.go` also removes at most 64 day-old private download directories per
preparation. Recent transfers and immutable serving/rollback generations remain
protected. Hosted cleanup regressions use only temporary private directories.
