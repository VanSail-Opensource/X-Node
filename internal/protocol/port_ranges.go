package protocol

import (
	"errors"
	"slices"
	"sort"
)

// FirewallPortRangesCapability identifies compact ACL ranges and exact forwarding maps.
const FirewallPortRangesCapability = "native_firewall_port_ranges_v1"

// MaxForwardMapElements bounds expanded native port-map entries across a policy.
const MaxForwardMapElements = 4 * 65535

// UsesPortRanges reports whether older agents would omit any firewall port settings.
func (p FirewallPolicy) UsesPortRanges() bool {
	if len(p.TCPPortRanges)+len(p.UDPPortRanges)+len(p.SSHPortRanges) > 0 {
		return true
	}
	for _, f := range p.Forward {
		if f.PortEnd != 0 || f.TargetPortEnd != 0 {
			return true
		}
	}
	return false
}

// NormalizePortRanges validates and canonicalizes port settings without expanding ranges.
// Legacy singleton fields remain readable; duplicates and covered singleton ports disappear.
func (p FirewallPolicy) NormalizePortRanges() (FirewallPolicy, error) {
	strict := p.UsesPortRanges()
	for _, group := range []struct {
		ports  *[]int
		ranges *[]PortRange
	}{{&p.TCPPorts, &p.TCPPortRanges}, {&p.UDPPorts, &p.UDPPortRanges}, {&p.SSHPorts, &p.SSHPortRanges}} {
		ranges, err := NormalizePortIntervals(*group.ranges)
		if err != nil {
			return p, err
		}
		ports := slices.Clone(*group.ports)
		slices.Sort(ports)
		ports = slices.Compact(ports)
		kept := ports[:0]
		for _, port := range ports {
			if port < 1 || port > 65535 {
				return p, errors.New("invalid firewall port")
			}
			index := sort.Search(len(ranges), func(i int) bool { return ranges[i].To >= port })
			if index == len(ranges) || ranges[index].From > port {
				kept = append(kept, port)
			}
		}
		*group.ports, *group.ranges = kept, ranges
	}
	var err error
	p.Forward, err = normalizeForwardRanges(p.Forward, strict)
	return p, err
}

// NormalizePortIntervals merges overlapping/adjacent firewall ranges. Protocol is
// selected by the owning field; an explicit Network is rejected to avoid ambiguity.
func NormalizePortIntervals(input []PortRange) ([]PortRange, error) {
	ranges := slices.Clone(input)
	for _, r := range ranges {
		if r.From < 1 || r.To < r.From || r.To > 65535 || r.Network != "" {
			return nil, errors.New("invalid firewall port range")
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].From == ranges[j].From {
			return ranges[i].To < ranges[j].To
		}
		return ranges[i].From < ranges[j].From
	})
	merged := ranges[:0]
	for _, r := range ranges {
		if len(merged) > 0 && r.From <= merged[len(merged)-1].To+1 {
			merged[len(merged)-1].To = max(merged[len(merged)-1].To, r.To)
		} else {
			merged = append(merged, r)
		}
	}
	return merged, nil
}

// PortBounds returns inclusive bounds; a zero optional end denotes one port.
func PortBounds(start, end int) (int, int) {
	if end == 0 {
		end = start
	}
	return start, end
}
