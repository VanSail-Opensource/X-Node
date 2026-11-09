package firewall

import (
	"crypto/sha256"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"net/netip"
)

// Retain the empty legacy chain so reconciliation removes previously installed
// redirects atomically. DNS interception belongs exclusively to Xray routing.
func (b *policyPlan) redirect(_ bool) {}
func (b *policyPlan) nat(forwards []protocol.Forward, redirect bool) {
	b.redirect(redirect)
	if len(forwards) == 0 {
		return
	}
	b.add("forward", "inbound-blacklist", direction(false, false), dnat(), jump("blacklist"))
	b.add("forward", "established", ctState(6, false), accept())
	b.add("forward", "invalid", ctState(expr.CtStateBitINVALID, false), b.eventDrop("invalid_packet"))
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
		from, to := protocol.PortBounds(f.Port, f.PortEnd)
		targetFrom, targetTo := protocol.PortBounds(f.TargetPort, f.TargetPortEnd)
		id := fmt.Sprintf("forward-%x", sha256.Sum256([]byte(fmt.Sprintf("%s/%d-%d/%s/%s/%d-%d", f.ListenIP, from, to, f.Network, target, targetFrom, targetTo))))
		if seen[id] {
			continue
		}
		seen[id] = true
		match := family(v6)
		if f.ListenIP != "" {
			ip := netip.MustParseAddr(f.ListenIP)
			match = address(netip.PrefixFrom(ip, ip.BitLen()).String(), true, false)
		}
		translation := expressions{&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(targetFrom))}}
		if targetTo != targetFrom {
			name := forwardingMapName(f)
			elements := make([]nftables.SetElement, 0, to-from+1)
			for port := from; port <= to; port++ {
				elements = append(elements, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(port)), Val: binaryutil.BigEndian.PutUint16(uint16(targetFrom + port - from))})
			}
			b.sets = append(b.sets, setSpec{set: &nftables.Set{Table: b.table, Name: name, KeyType: nftables.TypeInetService, DataType: nftables.TypeInetService, IsMap: true}, elements: elements})
			translation = expressions{&expr.Lookup{SourceRegister: 1, DestRegister: 2, IsDestRegSet: true, SetName: name}}
		}
		b.add("prerouting", id, match, portInterval(proto, from, to), translation, expressions{
			&expr.Immediate{Register: 1, Data: target.AsSlice()},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: fam, RegAddrMin: 1, RegProtoMin: 2},
		})
		b.add("forward", id, family(v6), dnat(), originalForward(f), address(netip.PrefixFrom(target, target.BitLen()).String(), true, false), portInterval(proto, targetFrom, targetTo), accept())
	}
	b.add("postrouting", "masquerade", dnat(), expressions{&expr.Masq{}})
}

func forwardingMapName(f protocol.Forward) string {
	// Target ports are values rather than identity, allowing atomic value updates.
	_, to := protocol.PortBounds(f.Port, f.PortEnd)
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s/%d-%d/%s/%s", f.ListenIP, f.Port, to, f.Network, f.TargetIP)))
	return fmt.Sprintf("forward_ports_%x", hash[:12])
}
func dnat() expressions {
	// Linux UAPI enum ip_conntrack_status: IPS_DST_NAT_BIT = 5.
	bits := binaryutil.NativeEndian.PutUint32(1 << 5)
	return cat(expressions{&expr.Ct{Register: 1, Key: expr.CtKeySTATUS}}, mask(bits), cmp(make([]byte, 4), true))
}
