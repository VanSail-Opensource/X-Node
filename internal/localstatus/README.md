# Local status query

`server.go` exposes one bounded JSON status response over `status.sock` inside
the existing private state directory. The socket is mode 0600, uses one response
worker and a one-second write deadline. Startup refuses regular files, symlinks,
public directories and live sockets; only a connection-refused stale socket is
removed. Cancellation closes the listener and shutdown joins its worker.

`client.go` provides the two-second, 4 KiB query used by `xnodectl status`.
Snapshots contain readiness, connectivity, revisions and the query time. They
contain no credentials, source IPs or persistent telemetry. No status JSON file
is written. `server_test.go` covers queries, permissions and path protection in
hosted Linux CI.
