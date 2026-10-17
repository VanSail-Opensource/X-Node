package protocol

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

func validateSourceListener(raw json.RawMessage, target SourceGeoIPListener) error {
	var root struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     any    `json:"port"`
			Protocol string `json:"protocol"`
			Stream   struct {
				Security string `json:"security"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &root) != nil {
		return errors.New("invalid source-filter listener document")
	}
	found := false
	for _, in := range root.Inbounds {
		if !portContains(in.Port, target.Port) || !listenOverlap(in.Listen, target.ListenIP) {
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
