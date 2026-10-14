package protocol

import "testing"

func TestDNSRedirectRejectsResolutionLoops(t *testing.T) {
	for _, servers := range []string{`["localhost"]`, `["1.1.1.1"]`, `["https://dns.example.com/dns-query"]`, `["https://127.0.0.1/dns-query"]`, `[]`} {
		c := Config{Xray: []byte(`{"inbounds":[],"dns":{"servers":` + servers + `}}`), Users: []User{}, DNS: DNSPolicy{Redirect: true}}
		if e := c.Validate(); e == nil {
			t.Fatalf("accepted upstream loop: %s", servers)
		}
	}
	c := Config{Xray: []byte(`{"inbounds":[],"dns":{"servers":["https://1.1.1.1/dns-query"]}}`), Users: []User{}, DNS: DNSPolicy{Redirect: true}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}
