package protocol

import "testing"

func TestScopedDNSAllowsLoopbackAndPublicResolvers(t *testing.T) {
	for _, servers := range []string{`["localhost"]`, `["127.0.0.1"]`, `["8.8.8.8"]`, `[{"address":"127.0.0.1","port":5353}]`, `["https://dns.example.com/dns-query"]`} {
		c := Config{Xray: []byte(`{"inbounds":[],"dns":{"servers":` + servers + `}}`), Users: []User{}, DNS: DNSPolicy{Redirect: true}}
		if e := c.Validate(); e != nil {
			t.Fatalf("rejected independent resolver %s: %v", servers, e)
		}
	}
	c := Config{Xray: []byte(`{"inbounds":[]}`), Users: []User{}, DNS: DNSPolicy{Redirect: true}}
	if c.Validate() == nil {
		t.Fatal("missing DNS configuration accepted")
	}
	c.DNS.Mode = "smartdns"
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}
