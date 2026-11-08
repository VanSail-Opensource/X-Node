package httpguard

import (
	"net/http"
	"strings"
	"testing"
)

func TestHTTPSURLValidatesWithoutImplicitPublicNetworkAssumptions(t *testing.T) {
	for _, raw := range []string{
		"https://example.com", "HTTPS://EXAMPLE.com:443/asset?name=a%20b", "https://localhost:8443/path",
		"https://127.0.0.1:443/", "https://10.0.0.1/", "https://[::1]:8443/", "https://[2001:db8::1]/", "https://[fe80::1%25eth0]/",
	} {
		t.Run(raw, func(t *testing.T) {
			if u, err := HTTPSURL(raw); err != nil || u.Scheme != "https" {
				t.Fatalf("explicit HTTPS endpoint rejected: %v", err)
			}
		})
	}
	for _, raw := range []string{
		"", "http://example.com", "https:opaque", "/relative", "https:///missing", "https://user:secret@example.com",
		"https://example.com/#fragment", "https://example.com/#", "https://example.com:0", "https://example.com:65536",
		"https://example.com:not-a-port", "https://example.com:", "https://[]/", "https://[not-ip]/", "https://2001:db8::1/",
		"https://example.com/\npath", "https://example.com/?secret=%0a", "https://example.com/%00", "https://example.com/\x7f",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := HTTPSURL(raw)
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "example.com") {
				t.Fatal("invalid endpoint accepted or revealed")
			}
		})
	}
}

func TestInitialIPv6ZoneHostUsesEscapedAuthority(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
		calls++
		return mockResponse(request, http.StatusOK, ""), nil
	}}}
	response, err := Do(client, requestForTest(t, http.MethodGet, "https://[fe80::1%25eth0]/path"), ExactOrigin)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if calls != 1 {
		t.Fatal("valid IPv6 zone endpoint did not reach its transport")
	}
}

func TestCanonicalOriginUsesHostCaseAndEffectivePort(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://EXAMPLE.com/", "https://example.com:443/"},
		{"https://example.com:00443/", "https://example.com/"},
		{"https://[2001:0db8:0:0::1]/", "https://[2001:db8::1]:443/"},
	} {
		left, err := HTTPSURL(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		right, err := HTTPSURL(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if urlOrigin(left) != urlOrigin(right) {
			t.Fatal("equivalent HTTPS origins diverged")
		}
	}
}

func TestInitialHostOverrideAndUnknownPolicyFailBeforeTransport(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
		calls++
		return mockResponse(request, http.StatusOK, ""), nil
	}}}
	request := requestForTest(t, http.MethodGet, "https://origin.example/path")
	request.Host = "other.example"
	if _, err := Do(client, request, ExactOrigin); err == nil {
		t.Fatal("Host override was authorized")
	}
	request.Host = "origin.example"
	if _, err := Do(client, request, Policy(255)); err == nil {
		t.Fatal("unknown policy was authorized")
	}
	if _, err := Do(client, nil, ExactOrigin); err == nil {
		t.Fatal("nil request was accepted")
	}
	if calls != 0 {
		t.Fatal("invalid initial request reached a transport")
	}
}
