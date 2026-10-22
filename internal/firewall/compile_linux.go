package firewall

import (
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"time"
)

type setSpec struct {
	set      *nftables.Set
	elements []nftables.SetElement
	preserve bool
}
type policyPlan struct {
	preserveRules map[string]bool
	policy        protocol.FirewallPolicy
	table         *nftables.Table
	chains        []*nftables.Chain
	rules         map[string][]*nftables.Rule
	sets          []setSpec
}

var counterNames = []string{"blocked_requests", "ban_events", "blacklist_drops", "syn_limited", "outbound_replies", "dns_redirects"}

func compile(p protocol.FirewallPolicy, redirect bool, ssh []int) (*policyPlan, error) {
	if err := validate(p, ssh); err != nil {
		return nil, err
	}
	b := &policyPlan{policy: p, table: &nftables.Table{Name: "x_node", Family: nftables.TableFamilyINet}, rules: map[string][]*nftables.Rule{}}
	for _, name := range []string{"ban_v6", "blocked_v4", "blocked_v6", "blocked", "refresh_v4", "refresh_v6"} {
		b.chain(name, nil, nil, "", false)
	}
	b.chain("input", nftables.ChainHookInput, nftables.ChainPriorityFilter, nftables.ChainTypeFilter, true)
	b.chain("output", nftables.ChainHookOutput, nftables.ChainPriorityFilter, nftables.ChainTypeFilter, false)
	b.chain("dns_output", nftables.ChainHookOutput, nftables.ChainPriorityRef(-110), nftables.ChainTypeNAT, false)
	b.chain("prerouting", nftables.ChainHookPrerouting, nftables.ChainPriorityNATDest, nftables.ChainTypeNAT, false)
	b.chain("forward", nftables.ChainHookForward, nftables.ChainPriorityFilter, nftables.ChainTypeFilter, len(p.Forward) > 0)
	b.chain("postrouting", nftables.ChainHookPostrouting, nftables.ChainPriorityNATSource, nftables.ChainTypeNAT, false)
	if err := b.staticSets(p, ssh); err != nil {
		return nil, err
	}
	if err := b.geoipSets(); err != nil {
		return nil, err
	}
	for _, pair := range []struct {
		name string
		v6   bool
		ttl  time.Duration
	}{
		{banSetV4, false, 72 * time.Hour}, {banSetV6, true, 72 * time.Hour},
		{"syn_v4", false, time.Minute}, {"syn_v6", true, time.Minute},
	} {
		key := nftables.TypeIPAddr
		if pair.v6 {
			key = nftables.TypeIP6Addr
		}
		size := uint32(65535)
		if pair.name == banSetV4 || pair.name == banSetV6 {
			size = banSetSize
		}
		b.sets = append(b.sets, setSpec{set: &nftables.Set{Table: b.table, Name: pair.name, KeyType: key, Dynamic: true, HasTimeout: true, Timeout: pair.ttl, Size: size}})
	}
	b.banSets()
	b.protection(p.Protect)
	b.input()
	b.networkEssentials(p.Protect)
	b.nat(p.Forward, redirect)
	return b, nil
}
func (b *policyPlan) chain(name string, hook *nftables.ChainHook, priority *nftables.ChainPriority, kind nftables.ChainType, deny bool) {
	c := &nftables.Chain{Name: name, Table: b.table, Hooknum: hook, Priority: priority, Type: kind}
	if hook != nil {
		policy := nftables.ChainPolicyAccept
		if deny {
			policy = nftables.ChainPolicyDrop
		}
		c.Policy = &policy
	}
	b.chains = append(b.chains, c)
}
func (b *policyPlan) add(chain, id string, groups ...expressions) {
	b.rules[chain] = append(b.rules[chain], &nftables.Rule{Table: b.table, Chain: &nftables.Chain{Table: b.table, Name: chain}, UserData: []byte("x-node:v1:" + id), Exprs: cat(groups...)})
}
func (b *policyPlan) input() {
	b.add("input", "loopback", meta(expr.MetaKeyIIFNAME, append([]byte("lo"), make([]byte, 14)...), false), accept())
	b.geoipDrops()
	for _, v6 := range []bool{false, true} {
		name := "trusted_v4"
		if v6 {
			name = "trusted_v6"
		}
		// Trusted sources bypass detection on open services, never the port ACL.
		b.add("input", fmt.Sprintf("trusted-tcp-%t", v6), sourceSet(v6, name, false, false), portSet(unix.IPPROTO_TCP, "tcp_ports", false), accept())
		b.add("input", fmt.Sprintf("trusted-udp-%t", v6), sourceSet(v6, name, false, false), portSet(unix.IPPROTO_UDP, "udp_ports", false), accept())
	}
	b.add("input", "blacklists", direction(false, false), jump("blacklist"))
	for i, raw := range []string{"127.0.0.0/8", "::1/128"} {
		for _, dest := range []bool{false, true} {
			b.add("input", fmt.Sprintf("spoof-loopback-%d-%t", i, dest), address(raw, dest, false), b.eventDrop("invalid_packet"))
		}
	}
	for i, raw := range []string{"0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"} {
		b.add("input", fmt.Sprintf("spoof-v4-%d", i), address(raw, false, false), b.eventDrop("invalid_packet"))
	}
	// IPv6 link essentials must precede unspecified/multicast rejection.
	b.ipv6Link()
	for i, raw := range []string{"::/128", "ff00::/8"} {
		b.add("input", fmt.Sprintf("spoof-v6-%d", i), address(raw, false, false), b.eventDrop("invalid_packet"))
	}
	b.add("input", "icmp-redirect", icmp(false, 5), b.eventDrop("icmp_probe"))
	b.add("input", "icmpv6-redirect", icmp(true, 137), b.eventDrop("icmp_probe"))
	b.add("input", "outbound-reply", direction(true, false), ctState(6, false), counter("outbound_replies"), accept())
	b.add("input", "invalid", ctState(expr.CtStateBitINVALID|expr.CtStateBitUNTRACKED, false), b.eventDrop("invalid_packet"))
	for i, bits := range []byte{3, 6, 5} {
		b.add("input", fmt.Sprintf("invalid-flags-%d", i), flags(bits, bits, false), b.eventDrop("invalid_packet"))
	}
	b.add("input", "established", ctState(6, false), accept())
	// Remaining input rules are appended by networkEssentials, after ICMP handling.
}
