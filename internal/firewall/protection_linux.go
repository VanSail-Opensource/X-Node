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
func (b *policyPlan) protection(enabled bool) {
	b.add("log_ban", "log", expressions{
		&expr.Limit{Type: expr.LimitTypePkts, Rate: 3, Unit: expr.LimitTimeMinute, Burst: 5},
		&expr.Log{Level: expr.LogLevelWarning, Key: (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_LEVEL), Data: []byte("x-node-ban72h: ")},
	}, verdict(expr.VerdictReturn, ""))
	b.add("ban_v6", "lan-exempt", sourceSet(true, "lan_v6", false, false), drop())
	b.add("ban_v6", "ban", dynamic(true, true, "banned_v6_64", unix.NFT_DYNSET_OP_UPDATE, 72*time.Hour), counter("ban_events"), jump("log_ban"))
	b.add("ban_v6", "drop", drop())
	for _, v6 := range []bool{false, true} {
		chain, lan, hits, ban, refresh := "blocked_v4", "lan_v4", "hits_v4", "banned_v4", "refresh_v4"
		if v6 {
			chain, lan, hits, ban, refresh = "blocked_v6", "lan_v6", "hits_v6", "banned_v6_64", "refresh_v6"
		}
		b.add(chain, "not-new", ctState(expr.CtStateBitNEW, true), drop())
		b.add(chain, "not-original", direction(false, true), drop())
		b.add(chain, "lan-exempt", sourceSet(v6, lan, false, false), drop())
		b.add(chain, "blocked-count", counter("blocked_requests"))
		if enabled {
			rate := &expr.Limit{Type: expr.LimitTypePkts, Rate: 1, Unit: expr.LimitTimeDay, Burst: 2, Over: true}
			hit := dynamic(v6, false, hits, unix.NFT_DYNSET_OP_ADD, 0, rate)
			if v6 {
				b.add(chain, "probe-ban", hit, goTo("ban_v6"))
			} else {
				b.add(chain, "probe-ban", hit, dynamic(false, false, ban, unix.NFT_DYNSET_OP_UPDATE, 72*time.Hour), counter("ban_events"), jump("log_ban"))
			}
		}
		b.add(chain, "drop", drop())
		b.add("blocked", fmt.Sprintf("family-%t", v6), family(v6), goTo(chain))
		b.add(refresh, "refresh", dynamic(v6, v6, ban, unix.NFT_DYNSET_OP_UPDATE, 72*time.Hour))
		b.add(refresh, "drop", counter("blacklist_drops"), drop())
	}
	b.add("blocked", "drop", drop())
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

func (b *policyPlan) networkEssentials(protected bool) {
	for _, kind := range []byte{3, 11, 12} {
		b.add("input", fmt.Sprintf("icmp-error-%d", kind), icmp(false, kind), accept())
	}
	for _, kind := range []byte{1, 2, 3, 4} {
		b.add("input", fmt.Sprintf("icmpv6-error-%d", kind), icmp(true, kind), accept())
	}
	b.add("input", "icmp-block", family(false), l4(unix.IPPROTO_ICMP), goTo("blocked_v4"))
	b.add("input", "icmpv6-block", family(true), l4(unix.IPPROTO_ICMPV6), goTo("blocked_v6"))
	b.add("input", "new-not-syn", ctState(expr.CtStateBitNEW, false), flags(0x17, 2, true), drop())
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
	if protected {
		for _, v6 := range []bool{false, true} {
			name := "syn_v4"
			if v6 {
				name = "syn_v6"
			}
			match := cat(family(v6), ctState(expr.CtStateBitNEW, false), portSet(unix.IPPROTO_TCP, "tcp_ports", false))
			limit := &expr.Limit{Type: expr.LimitTypePkts, Rate: 50, Unit: expr.LimitTimeSecond, Burst: 50, Over: true}
			action := drop()
			if v6 {
				action = goTo("ban_v6")
			}
			b.add("input", fmt.Sprintf("syn-limit-%t", v6), match, dynamic(v6, false, name, unix.NFT_DYNSET_OP_UPDATE, 0, limit), counter("syn_limited"), action)
			b.add("input", fmt.Sprintf("syn-overflow-%t", v6), match, sourceSet(v6, name, true, false), drop())
		}
	}
	b.add("input", "tcp-open", portSet(unix.IPPROTO_TCP, "tcp_ports", false), ctState(expr.CtStateBitNEW, false), accept())
	b.add("input", "udp-open", portSet(unix.IPPROTO_UDP, "udp_ports", false), ctState(expr.CtStateBitNEW, false), accept())
	b.add("input", "blocked", goTo("blocked"))
}
