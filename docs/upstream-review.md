# Upstream review ledger

Reviewed cedar2025/Xboard-Node PRs/issues against the Debian 13, Xray-only, WebSocket-only redesign on 2026-10-14. Status describes this repository's implementation; upstream issues and PRs were not closed or merged remotely.

## Pull requests

| PR | Status | Result |
| --- | --- | --- |
| #83 | Outside scope | OpenRC is removed; Debian systemd is the supported service manager |
| #82, #81 | Implemented | Online state is reported as periodic immutable snapshots, including unchanged connections |
| #80 | Implemented | Per-inbound/global configuration transitions, current authorization during failure/rollback, shared certificate profiles and validated activation |
| #79 | Implemented | Atomic admission/snapshots, credential replacement, actual session closure, TCP/UDP tracking and accurate managed-flow accounting |
| #78 | Implemented | Native listen addresses and IPv4/IPv6 configuration are retained |
| #77 | Implemented | Native Xray fallback fields are preserved |
| #74 | Implemented | Shared certificate managers and ACME storage across tagged inbounds |
| #73 | Superseded | sing-box user-index mutation paths are removed |
| #72 | Implemented | Typed remote runtime reload and utility command lifecycle |
| #71 | Implemented | Agent/core versions appear in hello and release metadata |
| #70 | Implemented | Same-ID credential changes remove old runtime identities before adding replacements |
| #64 | Implemented | Remote DNS propagation delay and certificate startup timeout |
| #60 | Superseded | Native Xray Freedom/socket options replace sing-box-specific direct outbound support |
| #51 | Outside scope | Hiddify/Xboard node-type adapters are removed |
| #44 | Superseded | One Debian bootstrap/service replaces binding and machine management |
| #43, #23, #22 | Outside scope | Alpine/OpenRC/Docker deployment is removed |
| #38, #36, #28 | Implemented | Native streamSettings, TLS/security, routing and DNS provider configuration retained without the original TLS fail-open fallback |
| #37 | Superseded | Legacy kernel-specific builders are replaced by native Xray validation |
| #32 | Implemented | Logical session registry performs targeted revocation and closure |
| #26 | Implemented | README and protocol/migration documentation rewritten |
| #25 | Implemented | Native XHTTP stream settings supported |
| #24 | Outside scope | Docker and multiple local instances removed |
| #9 | Implemented | Consistent native SS2022 account construction and explicit per-inbound credential overrides |
| #7 | Implemented | Active-IP limits count distinct canonical addresses, not transport sockets |

## Issues

| Issue | Status | Result |
| --- | --- | --- |
| #76 | Implemented | Native PROXY protocol/socket and fallback fields preserved |
| #69 | Implemented | Shared certificate profiles avoid per-inbound duplicate managers |
| #68, #21, #15 | Implemented | Public outbound-facing byte accounting, protected splice path and explicit upload/download report order |
| #67, #53, #47, #45 | Implemented | Authoritative user synchronization and credential generation revocation |
| #66, #65, #56, #55, #54, #52, #35, #33, #14, #10 | Superseded | sing-box/TUIC-specific behavior is removed; native Xray Hysteria support remains |
| #63, #40, #29 | Implemented | New typed schemas replace the incompatible weak device decoder; source-IP reports are requested explicitly |
| #62 | Outside scope | FreeBSD binaries are not part of Debian 13 support |
| #61, #13, #5 | Implemented | Exact WSS bootstrap URL, header authentication, bounded reconnect and snapshot reconciliation |
| #59 | Implemented | Native outbound socket/interface settings preserved |
| #58, #41 | Outside scope | Shadowsocks plugins unsupported by native core are rejected rather than approximated |
| #57, #42, #8 | Superseded | One agent/runtime manages tagged inbounds; legacy node/machine/multi-panel deployment modes removed |
| #50 | Implemented | Native outbound configuration requires valid protocols and tags |
| #49 | Implemented | Race-covered lifecycle, bounded background workers and systemd restart/watchdog |
| #48 | Implemented | Release binaries use trimmed paths and stripped symbols |
| #46 | Reviewed | The report lacked a concrete reproducible defect; general lifecycle regressions cover the redesigned runtime |
| #39 | Superseded | Native configuration replaces XrayR-style local configuration migration |
| #31, #16 | Implemented | Native transport/header settings are retained and core-validated |
| #30, #27 | Implemented | Tagged inbound updates isolate native encryption/transport configuration and replace changed listeners |
| #20 | Implemented | All native rules see managed Geo asset generations; required assets fail validation before listener changes |
| #19 | Implemented | Admission/accounting never wraps mux-facing concrete pipe readers |
| #18, #12, #6 | Implemented | Debian binaries, installer and local systemd CLI replace Docker |
| #17, #1 | Implemented | Native routing/outbounds, collision and dependency-cycle validation |
| #11 | Implemented | Managed Shadowsocks account generation and native user operations |
| #4 | Implemented | Boot ID, socket state, sampled timestamps and separate readiness/synchronization indicators |
| #3 | Implemented | Master controls use the typed WebSocket command channel |
| #2 | Implemented | Native PROXY protocol settings are preserved; source addresses come from authenticated session context |

Kernel-specific claims are validated using this repository's tests and selected upstream core. No Docker, OpenRC, FreeBSD or removed sing-box functionality is represented as supported.
