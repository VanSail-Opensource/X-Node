package firewall

import (
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/google/nftables/expr"
	"strings"
	"testing"
)

func TestSourceGeoIPDropsAreSilentAndBeforeEstablished(t *testing.T) {
	p := policy()
	p.SourceGeoIP = &protocol.SourceGeoIPPolicy{Generation: "v1", Prefixes: []string{"1.0.1.0/24", "1.0.2.0/23", "2001:4860::/32"}, Listeners: []protocol.SourceGeoIPListener{{Port: 443, Network: "tcp"}}}
	plan, err := compile(p, false, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	drops := 0
	for _, rule := range plan.rules["input"] {
		id := string(rule.UserData)
		if strings.HasSuffix(id, ":established") {
			if drops != 2 {
				t.Fatal("source filtering was not before established accept")
			}
			break
		}
		if !strings.Contains(id, ":source-geoip-") {
			continue
		}
		drops++
		for _, instruction := range rule.Exprs {
			if _, logged := instruction.(*expr.Log); logged {
				t.Fatal("source drop disclosed IP through NFLOG")
			}
		}
	}
	if drops != 2 {
		t.Fatal("IPv4/IPv6 source drops missing")
	}
}
