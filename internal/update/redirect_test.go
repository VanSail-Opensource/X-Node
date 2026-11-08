package update

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type releaseRedirectTransport func(*http.Request) (*http.Response, error)

func (f releaseRedirectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestReleaseDownloadsGuardEveryRedirectHop(t *testing.T) {
	for _, test := range []struct {
		source, target string
		allowed        bool
	}{
		{"https://api.github.com/repos/VanSail-Opensource/X-Node/releases/latest", "https://evil.example/release", false},
		{"https://github.com/VanSail-Opensource/X-Node/releases/download/v2.0.20/SHA256SUMS", "http://release-assets.githubusercontent.com/asset", false},
		{"https://github.com/VanSail-Opensource/X-Node/releases/download/v2.0.20/SHA256SUMS", "https://release-assets.githubusercontent.com/asset", true},
	} {
		calls := 0
		client := &http.Client{Transport: releaseRedirectTransport(func(request *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {test.target}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("verified-source")), Request: request}, nil
		})}
		manager := &Manager{Client: client}
		data, err := manager.fetch(context.Background(), test.source, 1024)
		if (err == nil) != test.allowed {
			t.Fatalf("release redirect decision differs: allowed=%t err=%v", test.allowed, err)
		}
		if test.allowed && string(data) != "verified-source" || !test.allowed && calls != 1 {
			t.Fatal("release client crossed its protected boundary")
		}
		if client.CheckRedirect != nil {
			t.Fatal("release policy mutated shared client")
		}
	}
}
