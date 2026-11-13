package protocol

import "testing"

func TestLiveDNSInputRejectsRetiredResolverSettings(t *testing.T) {
	for _, dns := range []string{`{"mode":"xray"}`, `{"mode":"smartdns","redirect":true}`, `{"mode":""}`, `{"upstreams":[]}`, `{"upstreams":["127.0.0.1"]}`} {
		if _, err := ParseConfig([]byte(`{"xray":{"inbounds":[]},"users":[],"dns":` + dns + `}`)); err == nil {
			t.Fatal("retired live DNS fields were accepted", dns)
		}
	}
	if _, err := ParseConfig([]byte(`{"xray":{"inbounds":[],"dns":{"servers":["127.0.0.1"]}},"users":[],"dns":{"redirect":true}}`)); err != nil {
		t.Fatal("explicit native resolver rejected", err)
	}
}
