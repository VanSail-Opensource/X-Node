package xray

import (
	"net/netip"
	"strings"
)

// RealityLogObservation classifies the pinned Xray TCP listener's explicit
// REALITY failures. Target errors and incomplete handshakes are not evidence.
func RealityLogObservation(text string) (InboundObservation, bool) {
	const prefix = "transport/internet/tcp: REALITY: processed invalid connection from "
	text, ok := strings.CutPrefix(text, prefix)
	if !ok {
		return InboundObservation{}, false
	}
	remote, reason, ok := strings.Cut(text, ": ")
	if !ok {
		return InboundObservation{}, false
	}
	addr, err := netip.ParseAddrPort(remote)
	if err != nil || addr.Addr().Zone() != "" {
		return InboundObservation{}, false
	}
	var rule string
	switch {
	case reason == "failed to read client hello":
		rule = "xray_tcp_probe"
	case strings.HasPrefix(reason, "unsupported TLS version: "), strings.HasPrefix(reason, "server name mismatch: "):
		rule = "xray_invalid"
	case reason == "authentication failed or validation criteria not met":
		rule = "xray_auth_failure"
	default:
		return InboundObservation{}, false
	}
	return InboundObservation{IP: addr.Addr().Unmap(), Rule: rule}, true
}
