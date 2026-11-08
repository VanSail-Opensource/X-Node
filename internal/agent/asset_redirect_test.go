package agent

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
)

type lazyRedirectTransport func(*http.Request) (*http.Response, error)

func (f lazyRedirectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestLazyAssetOuterClientOwnsRedirectBoundary(t *testing.T) {
	calls := 0
	inner := &http.Client{Transport: lazyRedirectTransport(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://foreign.example/private"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error {
		t.Error("lazy transport unexpectedly used inner redirect callback")
		return nil
	}}
	outer := &http.Client{Transport: &assetTransport{client: inner}}
	policy := geodata.Policy{Assets: []geodata.Asset{{URL: "https://approved.example/geosite.dat", File: "geosite.dat"}}}
	if _, err := geodata.Prepare(context.Background(), t.TempDir(), policy, nil, outer, true); err == nil {
		t.Fatal("lazy asset transport bypassed outer redirect policy")
	}
	if calls != 1 {
		t.Fatal("outer client followed a foreign location")
	}
}
