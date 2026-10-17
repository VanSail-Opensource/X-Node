package protocol

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

type sourceInbound struct {
	Listen   string `json:"listen"`
	Port     any    `json:"port"`
	Protocol string `json:"protocol"`
	Settings struct {
		Network string `json:"network"`
		UDP     bool   `json:"udp"`
	} `json:"settings"`
	Stream struct {
		Security string `json:"security"`
		Network  string `json:"network"`
	} `json:"streamSettings"`
}

func sourceInbounds(raw json.RawMessage) ([]sourceInbound, error) {
	var root struct {
		Inbounds []sourceInbound `json:"inbounds"`
	}
	if json.Unmarshal(raw, &root) != nil {
		return nil, errors.New("invalid source-filter listener document")
	}
	return root.Inbounds, nil
}
func inboundNetwork(in sourceInbound, network string) bool {
	switch in.Protocol {
	case "hysteria":
		return network == "udp"
	case "shadowsocks":
		return in.Settings.Network == "" || strings.Contains(in.Settings.Network, network)
	case "socks", "mixed":
		return network == "tcp" || in.Settings.UDP
	}
	switch in.Stream.Network {
	case "kcp", "quic", "hysteria":
		return network == "udp"
	}
	return network == "tcp"
}
func validateSourceListener(raw json.RawMessage, target SourceGeoIPListener) error {
	inbounds, err := sourceInbounds(raw)
	if err != nil {
		return err
	}
	found := false
	for _, in := range inbounds {
		if !portContains(in.Port, target.Port) || !listenOverlap(in.Listen, target.ListenIP) || !inboundNetwork(in, target.Network) {
			continue
		}
		if in.Stream.Security == "reality" {
			return errors.New("source GeoIP policy overlaps a REALITY listener")
		}
		if in.Protocol != "dokodemo-door" && in.Protocol != "tunnel" && (target.ListenIP == in.Listen || wildcardListen(in.Listen) && target.ListenIP == "") {
			found = true
		}
	}
	if !found {
		return errors.New("source GeoIP policy must reference an existing non-REALITY listener")
	}
	return nil
}

// SourceGeoIPListeners derives transport-accurate bindings using the same
// extraction and REALITY-overlap validation on the master and agent.
func SourceGeoIPListeners(raw json.RawMessage) ([]SourceGeoIPListener, error) {
	inbounds, err := sourceInbounds(raw)
	if err != nil {
		return nil, err
	}
	result := []SourceGeoIPListener{}
	seen := map[SourceGeoIPListener]bool{}
	for _, in := range inbounds {
		if in.Stream.Security == "reality" || in.Protocol == "dokodemo-door" || in.Protocol == "tunnel" {
			continue
		}
		for port := 1; port <= 65535; port++ {
			if !portContains(in.Port, port) {
				continue
			}
			for _, network := range []string{"tcp", "udp"} {
				if !inboundNetwork(in, network) {
					continue
				}
				binding := SourceGeoIPListener{ListenIP: in.Listen, Port: port, Network: network}
				if in.Listen == "::" {
					binding.ListenIP = ""
				}
				if seen[binding] {
					continue
				}
				if len(result) >= 256 {
					return nil, errors.New("too many non-REALITY listener bindings")
				}
				if err := validateSourceListener(raw, binding); err != nil {
					return nil, err
				}
				seen[binding] = true
				result = append(result, binding)
			}
		}
	}
	return result, nil
}
func wildcardListen(value string) bool { return value == "" || value == "0.0.0.0" || value == "::" }
func listenOverlap(a, b string) bool   { return a == b || wildcardListen(a) || wildcardListen(b) }
func portContains(value any, port int) bool {
	if number, ok := value.(float64); ok {
		return number == float64(port)
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, part := range strings.Split(text, ",") {
		low, high, span := strings.Cut(part, "-")
		from, err := strconv.Atoi(low)
		if err != nil {
			continue
		}
		to := from
		if span {
			to, err = strconv.Atoi(high)
		}
		if err == nil && port >= from && port <= to {
			return true
		}
	}
	return false
}
