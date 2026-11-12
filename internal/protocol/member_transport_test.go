package protocol

import (
	"encoding/json"
	"testing"
)

func memberTransportDocument(t *testing.T, stream string) json.RawMessage {
	t.Helper()
	raw := json.RawMessage(`{"outbounds":[{"tag":"peer","protocol":"vless","settings":{"vnext":[{"address":"8.8.8.8","port":443,"users":[{"id":"11111111-1111-1111-1111-111111111111"}]}]},"streamSettings":` + stream + `}]}`)
	if !json.Valid(raw) {
		t.Fatal("invalid fixture")
	}
	return raw
}

func TestMemberTransportCannotBypassEndpointOrOwnedPeerBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, stream string
		allowed      bool
	}{
		{"public download", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"1.1.1.1","port":443,"network":"xhttp"}}}`, true},
		{"private download", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp"}}}`, false},
		{"rebinding download", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"private.example","port":443,"network":"xhttp"}}}`, false},
		{"extra download", `{"network":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"address":"10.0.0.1","port":443,"network":"xhttp"}}}}`, false},
		{"legacy alias", `{"network":"splithttp","splithttpSettings":{"downloadSettings":{"address":"::1","port":443,"network":"xhttp"}}}`, false},
		{"case insensitive native fields", `{"network":"xhttp","XHTTPSettings":{"DownloadSettings":{"Address":"127.0.0.1","Port":443,"Network":"xhttp"}}}`, false},
		{"nested download", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"1.1.1.1","port":443,"network":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"address":"10.0.0.1","port":443,"network":"xhttp"}}}}}}`, false},
		{"nested foreign dialer", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"1.1.1.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"admin-outbound"}}}}`, false},
		{"nested owned dialer", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"1.1.1.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"peer"}}}}`, true},
		{"nested socket override", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"1.1.1.1","port":443,"network":"xhttp","sockopt":{"mark":1}}}}`, false},
		{"case insensitive socket", `{"Sockopt":{"dialerProxy":"admin-outbound"}}`, false},
		{"case insensitive file", `{"tlsSettings":{"certificates":[{"CertificateFile":"/node/private.pem"}]}}`, false},
		{"extra replaces inactive download", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"127.0.0.1"},"extra":{}}}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateMemberOutbounds(memberTransportDocument(t, test.stream), []string{"peer"})
			if (err == nil) != test.allowed {
				t.Fatalf("allowed=%v error=%v", test.allowed, err)
			}
		})
	}
}

func TestMemberProxyAddressRejectsNonPublicIPv6AndRetiredRelayRanges(t *testing.T) {
	for _, address := range []string{"fec0::1", "4000::1", "3fff::1", "2001:20::1", "192.88.99.1"} {
		if PublicProxyAddress(address) {
			t.Fatal("non-public or special-purpose proxy endpoint accepted", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if !PublicProxyAddress(address) {
			t.Fatal("public literal endpoint rejected", address)
		}
	}
}
