# Local administrative CLI

`main.go` exposes typed bootstrap, status, service, signed upgrade, firewall
recovery and uninstall operations. Production checks are Linux/capability based.
Tokens enter bootstrap over stdin and never appear in process arguments.

`upgrade.go` reads installed agent metadata before constructing the existing
signed updater. The installer invokes its newly verified staged CLI, allowing
replacement of an obsolete installed CLI that still rejects Ubuntu. The target
CLI version does not determine the installed agent version. Both executables
still pass signature/hash/version validation and the durable rollback contract.
`upgrade_test.go` verifies this older-agent/newer-CLI update decision through a
fake release transport, without contacting or mutating a host.
