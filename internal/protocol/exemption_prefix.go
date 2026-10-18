package protocol

import (
	"errors"
	"net/netip"
)

// ExemptionPrefix keeps exact IPv6 addresses at /128, independently of /64 bans.
func ExemptionPrefix(raw string) (netip.Prefix, error) {
	if ip, err := netip.ParseAddr(raw); err == nil {
		if ip.Zone() != "" {
			return netip.Prefix{}, errors.New("scoped exemption is not supported")
		}
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("invalid exemption prefix")
	}
	return p.Masked(), nil
}

func ExemptionKey(raw string) (string, error) {
	p, err := ExemptionPrefix(raw)
	if err != nil {
		return "", err
	}
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String(), nil
	}
	return p.String(), nil
}
