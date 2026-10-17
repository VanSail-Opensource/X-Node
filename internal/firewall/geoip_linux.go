package firewall

import (
	"bytes"
	"fmt"
	"github.com/google/nftables"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"net/netip"
	"sort"
)

func (b *policyPlan) geoipSets() error {
	for _, v6 := range []bool{false, true} {
		var builder netipx.IPSetBuilder
		if policy := b.policy.SourceGeoIP; policy != nil {
			for _, raw := range policy.Prefixes {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil {
					return err
				}
				if prefix.Addr().Is6() == v6 {
					builder.AddPrefix(prefix)
				}
			}
		}
		ips, err := builder.IPSet()
		if err != nil {
			return err
		}
		name, key := "source_geoip_v4", nftables.TypeIPAddr
		if v6 {
			name, key = "source_geoip_v6", nftables.TypeIP6Addr
		}
		var elements []nftables.SetElement
		for _, span := range ips.Ranges() {
			end := span.To().Next().AsSlice()
			if end == nil {
				end = make([]byte, key.Bytes)
			}
			elements = append(elements, nftables.SetElement{Key: span.From().AsSlice()}, nftables.SetElement{Key: end, IntervalEnd: true})
		}
		sort.Slice(elements, func(i, j int) bool {
			c := bytes.Compare(elements[i].Key, elements[j].Key)
			return c < 0 || c == 0 && elements[i].IntervalEnd && !elements[j].IntervalEnd
		})
		b.sets = append(b.sets, setSpec{set: &nftables.Set{Table: b.table, Name: name, KeyType: key, Interval: true, AutoMerge: true}, elements: elements})
	}
	return nil
}

func (b *policyPlan) geoipDrops() {
	if b.policy.SourceGeoIP == nil {
		return
	}
	for i, listener := range b.policy.SourceGeoIP.Listeners {
		proto := byte(unix.IPPROTO_TCP)
		if listener.Network == "udp" {
			proto = unix.IPPROTO_UDP
		}
		for _, v6 := range []bool{false, true} {
			name := "source_geoip_v4"
			if v6 {
				name = "source_geoip_v6"
			}
			var dest expressions
			if listener.ListenIP != "" {
				ip, err := netip.ParseAddr(listener.ListenIP)
				if err != nil || !ip.IsUnspecified() && ip.Is6() != v6 || ip.IsUnspecified() && ip.Is4() && v6 {
					continue
				}
				if !ip.IsUnspecified() {
					dest = address(netip.PrefixFrom(ip, ip.BitLen()).String(), true, false)
				}
			}
			// No NFLOG or detector hook: country drops never disclose source IPs.
			b.add("input", fmt.Sprintf("source-geoip-%d-%t", i, v6), direction(false, false), sourceSet(v6, name, false, false), dest, port(proto, uint16(listener.Port), true), drop())
		}
	}
}
