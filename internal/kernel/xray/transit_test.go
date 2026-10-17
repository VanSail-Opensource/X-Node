package xray

import (
	"context"
	"encoding/json"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealTransitRetainsAccountingAndCannotSurviveRevocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("works")) }))
	defer server.Close()
	registry := sessions.New()
	runtime := New(registry)
	defer runtime.Stop()
	config, port := testConfig(t)
	peerUUID := "550e8400-e29b-41d4-a716-446655440021"
	config.Users[0].BlockNew = true
	config.Users[0].AccountingPeriod = "paid-period"
	config.Users[0].TransitCredentials = []protocol.TransitCredential{{SourceNodeID: "source-node", InboundTag: "in", Generation: "generation-1", Credential: json.RawMessage(`{"id":"550e8400-e29b-41d4-a716-446655440021","encryption":"none"}`)}}
	registry.SetUsers(config.Users)
	if err := runtime.Apply(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if requestOK(testClient(t, port, testUUID, false), server.URL) {
		t.Fatal("ordinary credential bypassed global block")
	}
	peer := testClient(t, port, peerUUID, true)
	if !requestOK(peer, server.URL) {
		t.Fatal("peer credential could not authenticate")
	}
	awaitMeteredTraffic(t, registry, 1, 1, 1)
	registry.SampleActivity()
	if registry.Summary().Connections[1] != 0 || len(registry.ActiveIPs(1)) != 0 || len(registry.AccountingCounters()) != 1 {
		t.Fatal("peer was counted or not accounted")
	}
	previous := runtime.instance
	config.Users[0].TransitCredentials = nil
	registry.SetUsers(config.Users)
	if err := runtime.Apply(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if runtime.instance != previous {
		t.Fatal("peer revocation unnecessarily restarted listener")
	}
	if requestOK(peer, server.URL) {
		t.Fatal("revoked peer mux remained authorized")
	}
}
