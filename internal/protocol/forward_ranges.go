package protocol

import (
	"errors"
	"net/netip"
)

func normalizeForwardRanges(input []Forward, strict bool) ([]Forward, error) {
	if input == nil {
		return nil, nil
	}
	output := make([]Forward, 0, len(input))
	mapElements := 0
	for _, f := range input {
		from, to := PortBounds(f.Port, f.PortEnd)
		targetFrom, targetTo := PortBounds(f.TargetPort, f.TargetPortEnd)
		if from < 1 || to < from || to > 65535 || targetFrom < 1 || targetTo < targetFrom || targetTo > 65535 || f.Network != "tcp" && f.Network != "udp" {
			return nil, errors.New("invalid forwarding port range")
		}
		if targetTo != targetFrom && targetTo-targetFrom != to-from {
			return nil, errors.New("forwarding ranges must have equal lengths or one target port")
		}
		target, err := netip.ParseAddr(f.TargetIP)
		if err != nil || target.IsUnspecified() || target.IsMulticast() || strict && (target.Is4In6() || target.Zone() != "") {
			return nil, errors.New("invalid forwarding target address")
		}
		f.TargetIP = target.String()
		if f.ListenIP != "" {
			listen, err := netip.ParseAddr(f.ListenIP)
			if err != nil || listen.Is4() != target.Is4() || strict && (listen.Is4In6() || listen.Zone() != "" || listen.IsMulticast()) {
				return nil, errors.New("invalid forwarding listen address")
			}
			if listen.IsUnspecified() {
				f.ListenIP = ""
			} else {
				f.ListenIP = listen.String()
			}
		}
		if from == to {
			f.PortEnd = 0
		}
		if targetFrom == targetTo {
			f.TargetPortEnd = 0
		}
		duplicate := false
		for _, old := range output {
			if old == f {
				duplicate = true
				break
			}
			_, oldTo := PortBounds(old.Port, old.PortEnd)
			if strict && old.Network == f.Network && netip.MustParseAddr(old.TargetIP).Is4() == target.Is4() && (old.ListenIP == "" || f.ListenIP == "" || old.ListenIP == f.ListenIP) && from <= oldTo && old.Port <= to {
				return nil, errors.New("overlapping forwarding rules")
			}
		}
		if duplicate {
			continue
		}
		if targetTo != targetFrom {
			mapElements += to - from + 1
			if mapElements > MaxForwardMapElements {
				return nil, errors.New("too many forwarding map elements")
			}
		}
		output = append(output, f)
	}
	return output, nil
}
