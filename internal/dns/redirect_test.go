package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDiscoveryChecksInitialAndRedirectOrigins(t *testing.T) {
	var hits atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write([]byte("203.0.113.7")) }))
	defer foreign.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/address", http.StatusFound)
		case "/foreign":
			http.Redirect(w, r, foreign.URL, http.StatusFound)
		default:
			_, _ = w.Write([]byte("203.0.113.7"))
		}
	}))
	defer source.Close()
	if got, err := address(context.Background(), "auto", "", source.URL+"/same", true, source.Client()); err != nil || got != "203.0.113.7" {
		t.Fatalf("same-origin discovery failed: %s %v", got, err)
	}
	if _, err := address(context.Background(), "auto", "", source.URL+"/foreign", true, source.Client()); err == nil {
		t.Fatal("discovery crossed its approved origin")
	}
	if hits.Load() != 0 {
		t.Fatal("discovery contacted foreign origin")
	}
	for _, target := range []string{"http://127.0.0.1/private", "https://secret@lookup.example/"} {
		if _, err := address(context.Background(), "auto", "", target, true, source.Client()); err == nil {
			t.Fatal("direct discovery bypassed initial URL policy")
		}
	}
}
