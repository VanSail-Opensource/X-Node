package protocol

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestMemberProxyEndpointsCannotUsePrivateOrRebindingAddresses(t *testing.T) {
	for _, test := range []struct {
		address string
		allowed bool
	}{
		{"8.8.8.8", true}, {"2606:4700:4700::1111", true}, {"127.0.0.1", false}, {"10.0.0.1", false},
		{"::ffff:10.0.0.1", false}, {"100.64.0.1", false}, {"192.0.2.1", false}, {"proxy.example", false},
		{"64:ff9b::a00:1", false}, {"fe80::1%eth0", false},
	} {
		t.Run(test.address, func(t *testing.T) {
			raw := json.RawMessage(fmt.Sprintf(`{"outbounds":[{"tag":"peer-ming","protocol":"socks","settings":{"servers":[{"address":%q,"port":443}]}}]}`, test.address))
			if err := ValidateMemberOutbounds(raw, []string{"peer-ming"}); (err == nil) != test.allowed {
				t.Fatalf("allowed=%v,error=%v", test.allowed, err)
			}
		})
	}
}
