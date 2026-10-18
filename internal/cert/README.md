# Managed certificate profiles

`profiles.go` prepares shared managers and publishes them only after successful
activation. Node-file profiles reload bounded local PEM files on preparation;
their host files remain administrator-owned and are never removed by cleanup.
`file_material.go` limits each local certificate/key read to one MiB.

`material_cleanup.go` protects material and ACME storage for current and previous
distinct generations. Startup seeds protection from accepted private state.
Cleanup stops unused managers first and only removes owned hexadecimal cache
directories. Repeated no-op applies do not discard rollback material.

`validation.go` supplies temporary local/self-signed material for native
preflight. It validates actual file/content profiles without opening ACME
listeners, mutating DNS, or publishing active profile status. Issuance and renewal
belong to activation, with provider adapters in `dnsproviders`.
