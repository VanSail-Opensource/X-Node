package firewall

import (
	"crypto/sha256"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"net/netip"
)

func (b *policyPlan) redirect(enabled bool) {
	if !enabled {
		return
	}
	for _, v6 := range []bool{false, true} {
		for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
			b.add("dns_output", fmt.Sprintf("dns-%t-%d", v6, proto), family(v6), port(proto, 53, true), counter("dns_redirects"),
				expressions{&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(53)}, &expr.Redir{RegisterProtoMin: 1}})
		}
	}
}
func (b *policyPlan) nat(forwards []protocol.Forward, redirect bool) {
	b.redirect(redirect)
	if len(forwards) == 0 {
		return
	}
	b.add("forward", "established", ctState(6, false), accept())
	b.add("forward", "invalid", ctState(expr.CtStateBitINVALID, false), drop())
	seen := map[string]bool{}
	for _, f := range forwards {
		target := netip.MustParseAddr(f.TargetIP)
		v6 := target.Is6()
		fam := uint32(unix.NFPROTO_IPV4)
		if v6 {
			fam = unix.NFPROTO_IPV6
		}
		proto := byte(unix.IPPROTO_TCP)
		if f.Network == "udp" {
			proto = unix.IPPROTO_UDP
		}
		id := fmt.Sprintf("forward-%x", sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%s/%s/%d", f.ListenIP, f.Port, f.Network, target, f.TargetPort))))
		if seen[id] {
			continue
		}
		seen[id] = true
		match := family(v6)
		if f.ListenIP != "" {
			ip := netip.MustParseAddr(f.ListenIP)
			match = address(netip.PrefixFrom(ip, ip.BitLen()).String(), true, false)
		}
		b.add("prerouting", id, match, port(proto, uint16(f.Port), true), expressions{
			&expr.Immediate{Register: 1, Data: target.AsSlice()}, &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(f.TargetPort))},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: fam, RegAddrMin: 1, RegProtoMin: 2},
		})
		b.add("forward", id, dnat(), address(netip.PrefixFrom(target, target.BitLen()).String(), true, false), port(proto, uint16(f.TargetPort), true), accept())
	}
	b.add("postrouting", "masquerade", dnat(), expressions{&expr.Masq{}})
}
func dnat() expressions {
	// Linux UAPI enum ip_conntrack_status: IPS_DST_NAT_BIT = 5.
	bits := binaryutil.NativeEndian.PutUint32(1 << 5)
	return cat(expressions{&expr.Ct{Register: 1, Key: expr.CtKeySTATUS}}, mask(bits), cmp(make([]byte, 4), true))
}
