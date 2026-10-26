# Numerical compute kernels

`Run` executes an explicitly versioned batch of forecasts, regularized response
fits or candidate utility evaluations. Inputs are numerical snapshots and opaque
task IDs. The package has no credentials, database, commands or financial authority.
Both the panel and agent use these kernels, so local and remote results agree.

The transport bounds batches to 64 tasks / 256 KiB, uses single-threaded zstd
compression, and rejects compressed results above 1 MiB or decompression above
4 MiB. `ValidateResult` binds output to its original input; the panel still owns
policy checks, publication, billing and idempotent commits. New kernels require
a new explicit kind and compatible protocol/schema release.
