package geodata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestAssetRedirectsPreserveApprovedOriginAndExistingGeneration(t *testing.T) {
	var hits atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write([]byte("foreign")) }))
	defer foreign.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/asset", http.StatusFound)
		case "/foreign":
			http.Redirect(w, r, foreign.URL+"/private", http.StatusFound)
		default:
			_, _ = w.Write([]byte("approved"))
		}
	}))
	defer source.Close()
	dir := t.TempDir()
	policy := Policy{Assets: []Asset{{File: "geosite.dat", URL: source.URL + "/same"}}}
	if err := Ensure(context.Background(), dir, policy, nil, source.Client(), true); err != nil {
		t.Fatal(err)
	}
	previous := Resolve(dir)
	policy.Assets[0].URL = source.URL + "/foreign"
	if err := Ensure(context.Background(), dir, policy, nil, source.Client(), true); err == nil {
		t.Fatal("asset request crossed its approved origin")
	}
	if hits.Load() != 0 || Resolve(dir) != previous {
		t.Fatal("rejected redirect reached another host or changed active assets")
	}
	raw, err := os.ReadFile(filepath.Join(previous, "geosite.dat"))
	if err != nil || string(raw) != "approved" {
		t.Fatal("verified generation changed after rejected redirect")
	}
}

func TestAssetExecutionRejectsInvalidURLsBeforeTouchingCache(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/private", "https://user:secret@assets.example/geosite.dat", "https://assets.example/geosite.dat#fragment"} {
		dir := filepath.Join(t.TempDir(), "untouched")
		if _, err := Prepare(context.Background(), dir, Policy{Assets: []Asset{{File: "geosite.dat", URL: target}}}, nil, nil, false); err == nil {
			t.Fatal("direct policy construction bypassed initial URL validation")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("invalid policy changed the cache directory")
		}
	}
}
