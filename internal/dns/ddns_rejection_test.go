package dns

import (
	"context"
	"net/http"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type rejectedLookup struct{ t *testing.T }

func (r rejectedLookup) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("invalid DNS ownership/TTL reached address discovery")
	return nil, context.Canceled
}

func TestInvalidDDNSNeverDiscoversOrWritesProviderRecords(t *testing.T) {
	for _, mutate := range []func(*protocol.DDNSJob){
		func(j *protocol.DDNSJob) { j.TTLSeconds = protocol.MaxDDNSTTLSeconds + 1 },
		func(j *protocol.DDNSJob) { j.Name = "outside.invalid" },
		func(j *protocol.DDNSJob) { j.Name = "" },
	} {
		job := protocol.DDNSJob{ID: "wan", Zone: "example.com", Name: "node.example.com", IPv4: "auto", IPv4URL: "https://lookup.example/ip"}
		mutate(&job)
		provider := &setter{}
		if _, err := DDNS(context.Background(), job, provider, &http.Client{Transport: rejectedLookup{t}}); err == nil {
			t.Fatal("invalid DDNS job executed")
		}
		if len(provider.records) != 0 {
			t.Fatal("invalid DDNS job changed provider records")
		}
	}
}
