package firewall

import (
	"bytes"
	"net/netip"
	"sort"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func (b *policyPlan) portSet(proto byte, name string, invert bool) expressions {
	if b.policy.UsesPortRanges() {
		name += "_v2"
	}
	return portSet(proto, name, invert)
}

func (b *policyPlan) portRangeSets(p protocol.FirewallPolicy, ssh []int) error {
	tcp := append(append(append([]int(nil), p.TCPPorts...), p.SSHPorts...), ssh...)
	tcpRanges := append(append([]protocol.PortRange(nil), p.TCPPortRanges...), p.SSHPortRanges...)
	for _, group := range []struct {
		name   string
		ports  []int
		ranges []protocol.PortRange
	}{{"tcp_ports_v2", tcp, tcpRanges}, {"udp_ports_v2", p.UDPPorts, p.UDPPortRanges}} {
		for _, port := range group.ports {
			group.ranges = append(group.ranges, protocol.PortRange{From: port, To: port})
		}
		ranges, err := protocol.NormalizePortIntervals(group.ranges)
		if err != nil {
			return err
		}
		var elements []nftables.SetElement
		for _, r := range ranges {
			elements = append(elements,
				nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(r.From))},
				nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(uint16(r.To + 1)), IntervalEnd: true})
		}
		// Zero is the exclusive end sentinel when the last port is 65535.
		sort.Slice(elements, func(i, j int) bool {
			order := bytes.Compare(elements[i].Key, elements[j].Key)
			return order < 0 || order == 0 && elements[i].IntervalEnd && !elements[j].IntervalEnd
		})
		b.sets = append(b.sets, setSpec{set: &nftables.Set{Table: b.table, Name: group.name, KeyType: nftables.TypeInetService, Interval: true, AutoMerge: true}, elements: elements})
	}
	return nil
}

func portInterval(proto byte, from, to int) expressions {
	return cat(l4(proto), payload(expr.PayloadBaseTransportHeader, 2, 2), interval(from, to))
}

func interval(from, to int) expressions {
	if from == to {
		return cmp(binaryutil.BigEndian.PutUint16(uint16(from)), false)
	}
	return expressions{&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binaryutil.BigEndian.PutUint16(uint16(from)), ToData: binaryutil.BigEndian.PutUint16(uint16(to))}}
}

// Original tuple constraints keep forwarding authorization bound to the listener,
// even when another DNAT rule happens to choose the same destination service.
func originalForward(f protocol.Forward) expressions {
	from, to := protocol.PortBounds(f.Port, f.PortEnd)
	match := expressions{&expr.Ct{Key: expr.CtKeyPROTODST, Register: 1, Direction: expr.CtDirOriginal, OptDirection: true}}
	match = cat(match, interval(from, to))
	if f.ListenIP != "" {
		ip := netip.MustParseAddr(f.ListenIP)
		key := expr.CtKeyDSTIP
		if ip.Is6() {
			key = expr.CtKeyDSTIP6
		}
		match = cat(match, expressions{&expr.Ct{Key: key, Register: 1, Direction: expr.CtDirOriginal, OptDirection: true}}, cmp(ip.AsSlice(), false))
	}
	return match
}

// Delete only owned, obsolete static port sets after all rule references switch.
func (b *policyPlan) removeObsoletePortSets(c *nftables.Conn, exists bool) error {
	if !exists {
		return nil
	}
	keep := map[string]bool{}
	for _, spec := range b.sets {
		keep[spec.set.Name] = true
	}
	sets, err := c.GetSets(b.table)
	if err != nil {
		return err
	}
	for _, set := range sets {
		owned := set.Name == "tcp_ports" || set.Name == "udp_ports" || set.Name == "tcp_ports_v2" || set.Name == "udp_ports_v2" || strings.HasPrefix(set.Name, "forward_ports_")
		if owned && !keep[set.Name] {
			c.DelSet(set)
		}
	}
	return nil
}
