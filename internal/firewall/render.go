// Package firewall implements complete host nftables policy ownership with rollback.
package firewall

import (
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

func ports(values []int) string {
	seen := map[int]bool{}
	for _, p := range values {
		seen[p] = true
	}
	var sorted []int
	for p := range seen {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)
	var out []string
	for _, p := range sorted {
		out = append(out, strconv.Itoa(p))
	}
	return strings.Join(out, ", ")
}
func Render(p protocol.FirewallPolicy, redirect bool, ssh []int) ([]byte, error) {
	check := protocol.Config{Xray: []byte(`{"inbounds":[]}`), Users: []protocol.User{}, Firewall: p}
	if e := check.Validate(); e != nil {
		return nil, e
	}
	tcp := append(append([]int(nil), p.TCPPorts...), p.SSHPorts...)
	tcp = append(tcp, ssh...)
	if len(ssh) == 0 && len(p.SSHPorts) == 0 {
		return nil, fmt.Errorf("SSH listening ports must be known")
	}
	v4 := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	v6 := []string{"fc00::/7", "fe80::/10"}
	for _, raw := range p.AllowPrefixes {
		prefix, _ := netip.ParsePrefix(raw)
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix.Masked().String())
		} else {
			v6 = append(v6, prefix.Masked().String())
		}
	}
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\nflush ruleset\ntable inet x_node {\n")
	fmt.Fprintf(&b, " set lan_v4 { type ipv4_addr; flags interval; auto-merge; elements = { %s }; }\n set lan_v6 { type ipv6_addr; flags interval; auto-merge; elements = { %s }; }\n", strings.Join(v4, ", "), strings.Join(v6, ", "))
	b.WriteString(` set banned_v4 { type ipv4_addr; flags dynamic,timeout; timeout 72h; size 65535; }
 set banned_v6_64 { type ipv6_addr; flags dynamic,timeout; timeout 72h; size 65535; }
 set hits_v4 { type ipv4_addr; flags dynamic,timeout; timeout 24h; size 65535; }
 set hits_v6 { type ipv6_addr; flags dynamic,timeout; timeout 24h; size 65535; }
 set syn_v4 { type ipv4_addr; flags dynamic,timeout; timeout 1m; size 65535; }
 set syn_v6 { type ipv6_addr; flags dynamic,timeout; timeout 1m; size 65535; }
 counter blocked_requests { }
 counter ban_events { }
 counter blacklist_drops { }
 counter syn_limited { }
 counter outbound_replies { }
 counter dns_redirects { }
 chain log_ban { limit rate 3/minute burst 5 packets log prefix "x-node-ban72h: " level warn; return; }
 chain ban_v6 {
  ip6 saddr @lan_v6 drop
  update @banned_v6_64 { ip6 saddr & ffff:ffff:ffff:ffff:: timeout 72h } counter name ban_events jump log_ban
  drop
 }
 chain blocked_v4 {
  ct state != new drop
  ct direction != original drop
  ip saddr @lan_v4 drop
  counter name blocked_requests
`)
	if p.Protect {
		b.WriteString("  add @hits_v4 { ip saddr limit rate over 1/day burst 2 packets } update @banned_v4 { ip saddr timeout 72h } counter name ban_events jump log_ban\n")
	}
	b.WriteString("  drop\n }\n chain blocked_v6 {\n  ct state != new drop\n  ct direction != original drop\n  ip6 saddr @lan_v6 drop\n  counter name blocked_requests\n")
	if p.Protect {
		b.WriteString("  add @hits_v6 { ip6 saddr limit rate over 1/day burst 2 packets } goto ban_v6\n")
	}
	b.WriteString(`  drop
 }
 chain blocked { meta nfproto ipv4 goto blocked_v4; meta nfproto ipv6 goto blocked_v6; drop; }
 chain refresh_v4 { update @banned_v4 { ip saddr timeout 72h }; counter name blacklist_drops drop; }
 chain refresh_v6 { update @banned_v6_64 { ip6 saddr & ffff:ffff:ffff:ffff:: timeout 72h }; counter name blacklist_drops drop; }
 chain input {
  type filter hook input priority filter; policy drop;
  iifname "lo" accept
  iifname != "lo" ip saddr 127.0.0.0/8 drop
  iifname != "lo" ip daddr 127.0.0.0/8 drop
  ip saddr { 0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4 } drop
  iifname != "lo" ip6 saddr ::1 drop
  iifname != "lo" ip6 daddr ::1 drop
  ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type nd-router-advert ct state != invalid accept
  ip6 saddr { ::, fe80::/10 } ip6 hoplimit 255 icmpv6 type nd-router-solicit ct state != invalid accept
  ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ct state != invalid accept
  ip6 saddr { ::, fe80::/10 } ip6 hoplimit 1 icmpv6 type { 130, 131, 132, 143 } ct state != invalid accept
  ip6 saddr fe80::/10 udp sport 547 udp dport 546 ct state != invalid accept
  ip6 saddr { ::, ff00::/8 } drop
  icmp type redirect goto blocked_v4
  icmpv6 type nd-redirect goto blocked_v6
  ct direction reply ct state established,related counter name outbound_replies accept
  ct state invalid drop
  ct state untracked drop
  ct direction original ip saddr != @lan_v4 ip saddr @banned_v4 goto refresh_v4
  ct direction original ip6 saddr != @lan_v6 ip6 saddr & ffff:ffff:ffff:ffff:: @banned_v6_64 goto refresh_v6
  tcp flags & (fin | syn) == (fin | syn) goto blocked
  tcp flags & (syn | rst) == (syn | rst) goto blocked
  tcp flags & (fin | rst) == (fin | rst) goto blocked
  ct state established,related accept
  icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
  icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
  ip protocol icmp goto blocked_v4
  meta l4proto ipv6-icmp goto blocked_v6
  ct state new tcp flags & (fin | syn | rst | ack) != syn drop
  meta nfproto ipv4 udp sport 67 udp dport 68 accept
  meta nfproto ipv6 udp sport 547 udp dport 546 accept
`)
	tcpPorts := ports(tcp)
	udpPorts := ports(p.UDPPorts)
	if tcpPorts != "" {
		fmt.Fprintf(&b, "  tcp dport != { %s } goto blocked\n  ip saddr @lan_v4 tcp dport { %s } ct state new accept\n  ip6 saddr @lan_v6 tcp dport { %s } ct state new accept\n", tcpPorts, tcpPorts, tcpPorts)
	} else {
		b.WriteString("  meta l4proto tcp goto blocked\n")
	}
	if udpPorts != "" {
		fmt.Fprintf(&b, "  udp dport != { %s } goto blocked\n", udpPorts)
	} else {
		b.WriteString("  meta l4proto udp goto blocked\n")
	}
	if p.Protect && tcpPorts != "" {
		fmt.Fprintf(&b, "  meta nfproto ipv4 ct state new tcp dport { %s } update @syn_v4 { ip saddr limit rate over 50/second burst 50 packets } counter name syn_limited drop\n  meta nfproto ipv6 ct state new tcp dport { %s } update @syn_v6 { ip6 saddr limit rate over 50/second burst 50 packets } counter name syn_limited goto ban_v6\n  meta nfproto ipv4 ct state new tcp dport { %s } ip saddr != @syn_v4 drop\n  meta nfproto ipv6 ct state new tcp dport { %s } ip6 saddr != @syn_v6 drop\n", tcpPorts, tcpPorts, tcpPorts, tcpPorts)
	}
	if tcpPorts != "" {
		fmt.Fprintf(&b, "  tcp dport { %s } ct state new accept\n", tcpPorts)
	}
	if udpPorts != "" {
		fmt.Fprintf(&b, "  udp dport { %s } ct state new accept\n", udpPorts)
	}
	b.WriteString("  goto blocked\n }\n chain output { type filter hook output priority filter; policy accept; }\n chain dns_output { type nat hook output priority dstnat - 10; policy accept;\n")
	if redirect {
		b.WriteString("  meta nfproto ipv4 udp dport 53 counter name dns_redirects redirect to :53\n  meta nfproto ipv4 tcp dport 53 counter name dns_redirects redirect to :53\n  meta nfproto ipv6 udp dport 53 counter name dns_redirects redirect to :53\n  meta nfproto ipv6 tcp dport 53 counter name dns_redirects redirect to :53\n")
	}
	b.WriteString(" }\n")
	if len(p.Forward) > 0 {
		b.WriteString(" chain prerouting { type nat hook prerouting priority dstnat; policy accept;\n")
		for _, f := range p.Forward {
			target, _ := netip.ParseAddr(f.TargetIP)
			family := "ip"
			address := target.String() + ":" + strconv.Itoa(f.TargetPort)
			if target.Is6() {
				family = "ip6"
				address = "[" + target.String() + "]:" + strconv.Itoa(f.TargetPort)
			}
			match := "meta nfproto ipv4 "
			if target.Is6() {
				match = "meta nfproto ipv6 "
			}
			if f.ListenIP != "" {
				match = family + " daddr " + f.ListenIP + " "
			}
			fmt.Fprintf(&b, "  %s%s dport %d dnat %s to %s\n", match, f.Network, f.Port, family, address)
		}
		b.WriteString(" }\n chain forward { type filter hook forward priority filter; policy drop;\n  ct state established,related accept\n  ct state invalid drop\n")
		for _, f := range p.Forward {
			target, _ := netip.ParseAddr(f.TargetIP)
			family := "ip"
			if target.Is6() {
				family = "ip6"
			}
			fmt.Fprintf(&b, "  ct status dnat %s daddr %s %s dport %d accept\n", family, target.String(), f.Network, f.TargetPort)
		}
		b.WriteString(" }\n chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n  ct status dnat masquerade\n }\n")
	}
	b.WriteString("}\n")
	return []byte(b.String()), nil
}
