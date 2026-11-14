# X-Node nftables patch

This directory contains the complete Go module source for
`github.com/google/nftables` at
`v0.3.1-0.20260430172505-f9b52ed2ba65`, upstream commit
`f9b52ed2ba653815684ff3e19a4d087ff0b87332`.

The downloaded module archive was verified against the existing root `go.sum`
entry before extraction:

```
h1:git1jF54pv+jlZY51lOBW93GCdOq1K6ZXOzgyxrFJYM=
```

Archive SHA-256:
`e0a73b321d55113692d7f402707309ecbdb80897e6459c8bddfe7c4acaebaa23`.
The upstream Apache-2.0 license, notices, source, and tests are retained.

## Local change

Only `socket.go` changes upstream production code. Socket readiness uses a
zero-timeout `poll` instead of `pselect`, avoiding the fixed `FdSet` limit when a
netlink socket is allocated at descriptor 1024 or higher. Interrupted calls are
retried. EOF and socket errors remain readable; an invalid descriptor returns
`EBADF`. The raw-connection control scope, netlink receive deadlines, cancellation,
and transaction behavior are unchanged.

The same correction is proposed in upstream pull request
[google/nftables#352](https://github.com/google/nftables/pull/352), which was still
unmerged when this patch was prepared. The older pull-request base is not used:
the pinned revision's subsequent fixes are retained.

`socket_linux_test.go` adds unprivileged regression checks against the real
readiness method, including a Unix socket duplicated to descriptor 1024 or higher.
The tests do not send netlink commands or modify the host firewall. Root CI runs
them explicitly because `go test ./...` does not traverse nested modules:

```
go test -race -count=1 github.com/google/nftables -run '^TestSocketReadiness' -v
```

Remove the local replacement when a reviewed upstream revision incorporates the
descriptor fix and these regressions pass against that revision. No X-Node
version, release manifest, or production trust key is changed by this patch.
