# IP blocks and authorization publication

Existing authorized identity replacements preserve exact user-scoped source-IP
blocks. `protocol.UserReplacementIDs` checks the original authorization snapshots:
an actual move requires unchanged credentials and accounting period, an absent
source in the next snapshot, and an unoccupied target. Global blocks and unrelated
subjects stay unchanged. Transfers use original records and merge the later
deadline, without cascading through numeric identifiers.

Historical `replaces_id` metadata with an absent old principal proves no new
transfer. It does not prevent ordinary renewals or credential rotation. This
compatibility handling adds no account-relinking operation or endpoint.

`state.AuthorizeView` commits authorization and transferred blocks together.
Block/unblock commands capture the current credential/period subject and compare
it again inside the store transaction. Unknown or stale positive subjects fail;
global commands explicitly use subject zero. Drop-only operations compare the
captured subject in the registry and close only captured leases, without following
numeric aliases.

Successful authorization and IP-block changes return a detached
`state.AuthorizationView`. A process-local monotonic sequence orders publication;
`sessions.ApplyAuthorization` installs users and blocks under one admission lock
and ignores older views. Financial/traffic sequences remain independent, and the
publication sequence is never persisted or sent over the wire. Current users and
blocks are restored together before startup traffic is admitted.

Expiry removes only deadlines at or before the captured cutoff from the currently
persisted state. A later extension survives an older sweep. Failed writes publish
no new view. The existing store persistence lock remains authoritative; this does
not introduce another disk-held agent mutex.

Registry replacement retains live client reservations and existing accounting
generations. Native traffic counters retain their original user/period keys until
sampling and settlement complete; moving a restriction never moves old traffic.
Hosted regressions cover replacement/replay/restart, TCP/UDP admission, stale
subjects, reordered publications, expiry extensions, persistence failure, global
scope, numeric collisions and late original-period bytes.
