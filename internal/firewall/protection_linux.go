package firewall

import (
	"fmt"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"time"
)

func dynamic(v6, subnet bool, name string, operation uint32, ttl time.Duration, nested ...expr.Any) expressions {
	return cat(source(v6, subnet), expressions{&expr.Dynset{SrcRegKey: 1, SetName: name, Operation: operation, Timeout: ttl, Exprs: nested}})
}
func (b *policyPlan) protection(_ bool) {
	b.add("ban_v6", "report", b.eventDrop("syn_flood"))
	for _, v6 := range []bool{false, true} {
		chain, lan, refresh := "blocked_v4", "lan_v4", "refresh_v4"
		if v6 {
			chain, lan, refresh = "blocked_v6", "lan_v6", "refresh_v6"
		}
		action := drop()
		trusted := "trusted_v4"
		if v6 {
			trusted = "trusted_v6"
		}
		b.add(chain, "trusted", sourceSet(v6, trusted, false, false), action)
		b.add(chain, "not-new", ctState(expr.CtStateBitNEW, true), action)
		b.add(chain, "not-original", direction(false, true), action)
		b.add(chain, "lan-exempt", sourceSet(v6, lan, false, false), action)
		b.add(chain, "blocked-count", counter("blocked_requests"))
		b.add(chain, "report", b.event("closed_port"))
		b.add(chain, "drop", action)
		b.add("blocked", fmt.Sprintf("family-%t", v6), family(v6), goTo(chain))
		b.add(refresh, "report", b.event("blacklist"))
		b.add(refresh, "drop", counter("blacklist_drops"), drop())
	}
	action := drop()
	b.add("blocked", "drop", action)
}

func (b *policyPlan) ipv6Link() {
	valid := ctState(expr.CtStateBitINVALID, true)
	b.add("input", "router-advert", address("fe80::/10", false, false), hop(255), icmp(true, 134), valid, accept())
	for i, raw := range []string{"::/128", "fe80::/10"} {
		b.add("input", fmt.Sprintf("router-solicit-%d", i), address(raw, false, false), hop(255), icmp(true, 133), valid, accept())
		for _, kind := range []byte{130, 131, 132, 143} {
			b.add("input", fmt.Sprintf("mld-%d-%d", i, kind), address(raw, false, false), hop(1), icmp(true, kind), valid, accept())
		}
	}
	for _, kind := range []byte{135, 136} {
		b.add("input", fmt.Sprintf("neighbor-%d", kind), hop(255), icmp(true, kind), valid, accept())
	}
	b.add("input", "dhcpv6-link", address("fe80::/10", false, false), port(unix.IPPROTO_UDP, 547, false), port(unix.IPPROTO_UDP, 546, true), valid, accept())
}

func (b *policyPlan) networkEssentials(_ bool) {
	for _, kind := range []byte{3, 11, 12} {
		b.add("input", fmt.Sprintf("icmp-error-%d", kind), icmp(false, kind), accept())
	}
	for _, kind := range []byte{1, 2, 3, 4} {
		b.add("input", fmt.Sprintf("icmpv6-error-%d", kind), icmp(true, kind), accept())
	}
	b.add("input", "icmp-block", family(false), l4(unix.IPPROTO_ICMP), b.eventDrop("icmp_probe"))
	b.add("input", "icmpv6-block", family(true), l4(unix.IPPROTO_ICMPV6), b.eventDrop("icmp_probe"))
	b.add("input", "new-not-syn", ctState(expr.CtStateBitNEW, false), flags(0x17, 2, true), b.eventDrop("invalid_packet"))
	b.add("input", "dhcpv4", family(false), port(unix.IPPROTO_UDP, 67, false), port(unix.IPPROTO_UDP, 68, true), accept())
	b.add("input", "dhcpv6", family(true), port(unix.IPPROTO_UDP, 547, false), port(unix.IPPROTO_UDP, 546, true), accept())
	b.add("input", "tcp-closed", portSet(unix.IPPROTO_TCP, "tcp_ports", true), goTo("blocked"))
	for _, v6 := range []bool{false, true} {
		lan := "lan_v4"
		if v6 {
			lan = "lan_v6"
		}
		b.add("input", fmt.Sprintf("lan-tcp-%t", v6), sourceSet(v6, lan, false, false), portSet(unix.IPPROTO_TCP, "tcp_ports", false), ctState(expr.CtStateBitNEW, false), accept())
	}
	b.add("input", "udp-closed", portSet(unix.IPPROTO_UDP, "udp_ports", true), goTo("blocked"))
	if _, enabled := b.policy.Rule("syn_flood"); enabled {
		for _, v6 := range []bool{false, true} {
			name := "syn_v4"
			if v6 {
				name = "syn_v6"
			}
			match := cat(family(v6), ctState(expr.CtStateBitNEW, false), portSet(unix.IPPROTO_TCP, "tcp_ports", false))
			limit := &expr.Limit{Type: expr.LimitTypePkts, Rate: 50, Unit: expr.LimitTimeSecond, Burst: 50, Over: true}
			action := cat(b.eventDrop("syn_flood"))
			if v6 {
				action = goTo("ban_v6")
			}
			b.add("input", fmt.Sprintf("syn-limit-%t", v6), match, dynamic(v6, false, name, unix.NFT_DYNSET_OP_UPDATE, 0, limit), counter("syn_limited"), action)
			b.add("input", fmt.Sprintf("syn-overflow-%t", v6), match, sourceSet(v6, name, true, false), b.eventDrop("syn_flood"))
		}
	}
	b.add("input", "tcp-open", portSet(unix.IPPROTO_TCP, "tcp_ports", false), ctState(expr.CtStateBitNEW, false), accept())
	b.add("input", "udp-open", portSet(unix.IPPROTO_UDP, "udp_ports", false), ctState(expr.CtStateBitNEW, false), accept())
	b.add("input", "blocked", goTo("blocked"))
}
