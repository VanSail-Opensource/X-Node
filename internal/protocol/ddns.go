package protocol

import (
	"errors"
	"net/netip"
	"time"
)

// The reserved value cannot collide with a legacy named provider, whose key
// must pass ValidName. Built-in discovery does not publish public DNS records.
const BuiltinDDNSProvider = "builtin:panel"
const BuiltinDDNSCapability = "builtin_ddns_v1"
const DDNSChangesCapability = "ddns_changes_v1"
const DDNSChangesHeader = "X-XNode-DDNS-Changes"
const DDNSChangesFormat = "acknowledged-v1"
const MaxDDNSChangesPerFrame = 16

type DDNSChange struct {
	ID         string    `json:"id"`
	JobID      string    `json:"job_id"`
	Generation string    `json:"generation"`
	Sequence   uint64    `json:"sequence"`
	IPv4       string    `json:"ipv4,omitempty"`
	IPv6       string    `json:"ipv6,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
type DDNSChanges struct {
	Changes []DDNSChange `json:"changes"`
}
type DDNSChangeAck struct {
	IDs []string `json:"ids"`
}

func (c DDNSChange) Validate() error {
	if !ValidName(c.ID) || !ValidName(c.JobID) || !ValidName(c.Generation) || c.Sequence == 0 || c.ObservedAt.IsZero() || c.IPv4 == "" && c.IPv6 == "" {
		return errors.New("invalid DDNS change")
	}
	for index, value := range []string{c.IPv4, c.IPv6} {
		if value == "" {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.IsGlobalUnicast() || ip.Unmap().Is4() != (index == 0) || ip.Unmap().String() != value {
			return errors.New("invalid DDNS change address")
		}
	}
	return nil
}
