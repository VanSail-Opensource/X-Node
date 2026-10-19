# Managed certificate profiles

`profiles.go` prepares shared managers and publishes them only after successful
activation. Node-file profiles reload bounded local PEM files on preparation;
their host files remain administrator-owned and are never removed by cleanup.
`file_material.go` limits each local certificate/key read to one MiB.

`material_cleanup.go` protects material and ACME storage for current and previous
distinct generations. Startup seeds protection from accepted private state.
Cleanup stops unused managers first and only removes owned hexadecimal cache
directories. Repeated no-op applies do not discard rollback material.

`material_candidates.go` retires managers/material from abandoned preparations.
`RetainRuntime` protects material immediately after runtime application, including
when later firewall/state work fails before `Commit`. Cleanup never touches
administrator-owned input paths and removes at most 64 cache directories per pass.

`validation.go` supplies temporary local/self-signed material for native
preflight. It validates actual file/content profiles without opening ACME
listeners, mutating DNS, or publishing active profile status. Issuance and renewal
belong to activation, with provider adapters in `dnsproviders`.
