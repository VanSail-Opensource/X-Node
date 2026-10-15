package protocol

import (
	"encoding/json"
	"errors"
	"strings"
)

// AuxiliaryInboundTags identifies native forwarding/utility listeners. These
// listeners have no managed account and cannot be assigned to panel users.
func AuxiliaryInboundTags(raw json.RawMessage) ([]string, error) {
	var root struct {
		Inbounds []struct {
			Tag      string                     `json:"tag"`
			Protocol string                     `json:"protocol"`
			Settings map[string]json.RawMessage `json:"settings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &root) != nil {
		return nil, errors.New("invalid auxiliary inbound document")
	}
	tags := []string{}
	seen := map[string]bool{}
	for _, inbound := range root.Inbounds {
		if inbound.Protocol != "dokodemo-door" && inbound.Protocol != "tunnel" {
			continue
		}
		if !ValidName(inbound.Tag) || seen[inbound.Tag] || strings.HasPrefix(inbound.Tag, "_xnode_") {
			return nil, errors.New("invalid auxiliary inbound tag")
		}
		for _, key := range []string{"clients", "users", "accounts"} {
			if _, exists := inbound.Settings[key]; exists {
				return nil, errors.New("auxiliary listeners cannot contain account lists")
			}
		}
		seen[inbound.Tag] = true
		tags = append(tags, inbound.Tag)
	}
	return tags, nil
}

func validateAuxiliaryUsers(config Config) error {
	tags, err := AuxiliaryInboundTags(config.Xray)
	if err != nil {
		return err
	}
	auxiliary := map[string]bool{}
	for _, tag := range tags {
		auxiliary[tag] = true
	}
	for _, user := range config.Users {
		for _, tag := range user.InboundTags {
			if auxiliary[tag] {
				return errors.New("managed users cannot bind auxiliary listeners")
			}
		}
	}
	return nil
}
