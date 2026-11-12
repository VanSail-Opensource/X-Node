package protocol

import (
	"encoding/json"
	"testing"
)

func TestXHTTPPolicyValidatesOnlyEffectiveHTTP2Settings(t *testing.T) {
	for _, test := range []struct {
		name, stream string
		valid        bool
	}{
		{"absent", `{}`, true},
		{"valid", `{"xhttpSettings":{"h2Params":{"MaxConcurrentStreams":64,"SendPingTimeout":1000000}}}`, true},
		{"null", `{"xhttpSettings":{"h2Params":null}}`, true},
		{"unknown native field", `{"xhttpSettings":{"h2Params":{"futureField":true}}}`, true},
		{"invalid type", `{"xhttpSettings":{"h2Params":{"MaxConcurrentStreams":"bad"}}}`, false},
		{"invalid object", `{"xhttpSettings":{"h2Params":[]}}`, false},
		{"legacy alias", `{"splithttpSettings":{"h2Params":{"MaxConcurrentStreams":"bad"}}}`, false},
		{"preferred alias", `{"xhttpSettings":{"h2Params":{}},"splithttpSettings":{"h2Params":false}}`, true},
		{"null preferred alias", `{"xhttpSettings":null,"splithttpSettings":{"h2Params":false}}`, false},
		{"extra overrides", `{"xhttpSettings":{"h2Params":false,"extra":{"h2Params":{}}}}`, true},
		{"empty extra discards direct", `{"xhttpSettings":{"h2Params":false,"extra":{}}}`, true},
		{"null extra discards direct", `{"xhttpSettings":{"h2Params":false,"extra":null}}`, true},
		{"invalid extra wins", `{"xhttpSettings":{"h2Params":{},"extra":{"h2Params":false}}}`, false},
		{"extra is not recursive", `{"xhttpSettings":{"extra":{"h2Params":{},"extra":{"h2Params":false}}}}`, true},
		{"scalar extra", `{"xhttpSettings":{"extra":7}}`, false},
		{"download invalid", `{"xhttpSettings":{"downloadSettings":{"xhttpSettings":{"h2Params":false}}}}`, false},
		{"extra download invalid", `{"xhttpSettings":{"extra":{"downloadSettings":{"xhttpSettings":{"h2Params":false}}}}}`, false},
		{"extra discards download", `{"xhttpSettings":{"downloadSettings":{"xhttpSettings":{"h2Params":false}},"extra":{}}}`, true},
		{"download alias and extra", `{"xhttpSettings":{"downloadSettings":{"address":"8.8.8.8","port":443,"network":"xhttp","splithttpSettings":{"h2Params":false,"extra":{}}}}}`, true},
		{"TLS placeholder", `{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/missing/cert","keyFile":"/missing/key"}]},"xhttpSettings":{"h2Params":{}}}`, true},
		{"download TLS placeholder", `{"xhttpSettings":{"downloadSettings":{"address":"8.8.8.8","port":443,"network":"xhttp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/missing/cert","keyFile":"/missing/key"}]},"xhttpSettings":{"h2Params":{}}}}}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, direction := range []string{"inbounds", "outbounds"} {
				raw := json.RawMessage(`{"` + direction + `":[{"streamSettings":` + test.stream + `}]}`)
				if err := ValidateNativePolicies(Config{Xray: raw}); (err == nil) != test.valid {
					t.Fatalf("%s: valid=%v error=%v", direction, test.valid, err)
				}
			}
		})
	}
}
