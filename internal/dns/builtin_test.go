package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/libdns/libdns"
)

type forbiddenBuiltinSetter struct{ t *testing.T }

func (s forbiddenBuiltinSetter) SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	s.t.Error("built-in provider published DNS records")
	return nil, nil
}

func TestBuiltinDDNSDiscoversFamiliesWithoutProviderCredentials(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v6" {
			_, _ = w.Write([]byte("2001:db8::7"))
		} else {
			_, _ = w.Write([]byte("203.0.113.7"))
		}
	}))
	defer server.Close()
	for _, family := range []string{"v4", "v6", "both"} {
		job := protocol.DDNSJob{ID: "wan", Provider: protocol.BuiltinDDNSProvider}
		if family != "v6" {
			job.IPv4, job.IPv4URL = "auto", server.URL+"/v4"
		}
		if family != "v4" {
			job.IPv6, job.IPv6URL = "auto", server.URL+"/v6"
		}
		result, err := DDNS(context.Background(), job, forbiddenBuiltinSetter{t}, server.Client())
		if err != nil || result.Updated.IsZero() || family != "v6" && result.IPv4 != "203.0.113.7" || family != "v4" && result.IPv6 != "2001:db8::7" {
			t.Fatal(family, result, err)
		}
	}
	job := protocol.DDNSJob{ID: "wan", Provider: protocol.BuiltinDDNSProvider, IPv4: "auto", IPv4URL: server.URL + "/v6"}
	if result, err := DDNS(context.Background(), job, nil, server.Client()); err == nil || result.IPv4 != "" || !result.Updated.IsZero() {
		t.Fatal("failed discovery produced a new address", result, err)
	}
}
