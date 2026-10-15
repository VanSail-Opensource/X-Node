# Third-party notices

X-Node retains and adapts certificate/provider and logging code from cedar2025/Xboard-Node, originally described as MPL-2.0. The repository's MPL-2.0 text is in LICENSE.

Xray-core is MPL-2.0. The runtime uses its public feature/configuration interfaces; upstream copyright and license remain with XTLS contributors. Public integration patterns were reviewed in Mtoly/XrayRP (MPL-2.0); this project implements its own session registry and handler wrappers.

Komari-agent (MIT) informed the Debian metrics inventory and collection approach. Remnawave Node, Xray Checker and Xray Torrent Blocker were consulted for behavior; their source is not incorporated wholesale.

Go module dependencies retain their respective licenses, including CertMagic (Apache-2.0), libdns/provider libraries, Gorilla WebSocket (BSD-2-Clause), gopsutil (BSD-3-Clause), Minisign (MIT) and Go supplementary libraries (BSD-3-Clause). Release source includes go.mod/go.sum for the exact dependency inventory.

The firewall's typed rule/set and incremental reconciliation design was informed by ngrok/firewall_toolkit (MIT). Its source and managers are not incorporated. The native backend uses google/nftables v0.3.0 (Apache-2.0), mdlayher/netlink (MIT), and netipx (BSD-3-Clause); their licenses remain with the respective authors.
