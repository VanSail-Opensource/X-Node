package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"time"
)

const nfLogGroup = 100

func (b *policyPlan) event(rule string) expressions {
	if rule != "blacklist" && !b.policy.MasterControlled {
		return nil
	}
	if rule != "blacklist" {
		if _, enabled := b.policy.Rule(rule); !enabled {
			return nil
		}
	}
	name := "event_" + rule
	if _, exists := b.rules[name]; !exists {
		b.chain(name, nil, nil, "", false)
		b.add(name, "sample", expressions{&expr.Limit{Type: expr.LimitTypePkts, Rate: 1000, Unit: expr.LimitTimeSecond, Burst: 1000}, &expr.Log{Group: nfLogGroup, Snaplen: 32, QThreshold: 1, Key: (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_GROUP) | (1 << unix.NFTA_LOG_SNAPLEN) | (1 << unix.NFTA_LOG_QTHRESHOLD), Data: []byte("x-node:" + rule)}})
		b.add(name, "return", verdict(expr.VerdictReturn, ""))
	}
	return jump(name)
}

func (b *policyPlan) banSets() {
	b.chain("blacklist", nil, nil, "", false)
	b.preserveRules = map[string]bool{}
	for _, v6 := range []bool{false, true} {
		suffix, key, ban, lan, refresh := "v4", nftables.TypeIPAddr, "banned_v4", "lan_v4", "refresh_v4"
		if v6 {
			suffix, key, ban, lan, refresh = "v6", nftables.TypeIP6Addr, "banned_v6_64", "lan_v6", "refresh_v6"
		}
		b.sets = append(b.sets, setSpec{set: &nftables.Set{Table: b.table, Name: "exempt_" + suffix, KeyType: key, HasTimeout: true, Timeout: 72 * time.Hour, Dynamic: true, Size: 1 << 20}, preserve: true})
		b.chain("source_lookup_"+suffix, nil, nil, "", false)
		b.preserveRules["source_lookup_"+suffix] = true
		b.add("blacklist", "exempt-"+suffix, sourceSet(v6, "exempt_"+suffix, false, false), verdict(expr.VerdictReturn, ""))
		b.add("blacklist", "lan-"+suffix, sourceSet(v6, lan, false, false), verdict(expr.VerdictReturn, ""))
		b.add("blacklist", "banned-"+suffix, sourceSet(v6, ban, false, v6), goTo(refresh))
		b.add("blacklist", "source-"+suffix, family(v6), jump("source_lookup_"+suffix))
	}
	b.add("blacklist", "return", verdict(expr.VerdictReturn, ""))
}
