# Recover an agent with an obsolete updater

Use this procedure when an agent repeatedly hits the systemd watchdog, stays
connected but not ready, or cannot complete an upgrade. Preserve enrollment,
credentials, accounting journals, firewall recovery state and desired config.

## Diagnose before changing the host

Record `systemctl status x-node.service x-node-upgrade-rollback.service`, recent
`journalctl -u x-node.service`, `/var/lib/x-node/status.json`, and
`/var/lib/x-node/updates/transaction.json`. Do not publish tokens or private state.
Inspect `lslocks` and the rollback unit's process tree. An old helper waiting for
`systemctl restart` while holding the update lock must exit before installing.
Do not delete a live lock file: another inode permits simultaneous writers.

## Release the helper and preserve state

Run as root during a maintenance window:

```sh
systemctl stop x-node-upgrade-rollback.timer x-node-upgrade-rollback.service
systemctl stop --no-block x-node.service
```

Wait until both service processes have exited and `lslocks` shows no owner for
the update lock. If a helper ignores its stop deadline, inspect its PID/unit
again before terminating that unit's remaining processes with `systemctl kill`.
Create a root-only backup of `/etc/x-node`, `/var/lib/x-node`, both installed
binaries, and the systemd units/drop-ins. Never clear `state.json`, traffic
journals, `jobs.json`, firewall ownership snapshots or the enrollment token.

## Install a verified replacement

Fetch the stable release's installer, `SHA256SUMS`, signature, and both binaries
for the host architecture from the official X-Node release. Verify the manifest
using the independently trusted production Minisign key, then verify every
artifact against it. Do not trust a key downloaded beside the manifest.
Use the verified installer, which delegates upgrades to the newly verified CLI.
If the old transaction is still `pending`, retain its rollback files and use the
verified CLI's `rollback` first; wait for its restart before installing again.
Do not edit a transaction to `confirmed` to bypass recovery.

For missing `geosite.dat`, retain the incident's temporary asset-path drop-in
until the fixed release is installed. The fixed agent injects the verified
generation before validation and does not depend on ambient environment. Remove
the temporary drop-in only after a verified fixed-release restart.

## Acceptance and cleanup

Start with `systemctl start --no-block x-node.service`. Verify the new version,
`ready=true`, `synchronized=true`, matching desired/configuration revisions, and
listeners on every configured inbound port. Confirm master traffic acknowledgments
continue and the update transaction becomes `confirmed`; connectivity alone is
insufficient. Retain the backup until these checks pass. On failure restore the
saved binary pair/private state through the reviewed rollback procedure. Never
create a new enrollment identity to resolve an updater lock.
