package dnsproviders

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestVultrBearerNeverFollowsRetargetingRedirect(t *testing.T) {
	var hits atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	defer foreign.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer constructed-secret" {
			t.Error("approved provider request lost its bearer")
		}
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/resource", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/foreign" {
			http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer source.Close()
	provider := &vultrProvider{base: source.URL, client: source.Client(), token: "constructed-secret"}
	if err := provider.request(context.Background(), "GET", "/same", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := provider.request(context.Background(), "GET", "/foreign", nil, nil); err == nil {
		t.Fatal("provider followed foreign redirect")
	}
	if hits.Load() != 0 {
		t.Fatal("credentialed provider request reached another origin")
	}
}
