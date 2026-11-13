package geodata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPrivateAssetPublicationRetainsServingAndRollbackGenerations(t *testing.T) {
	var body atomic.Value
	body.Store("first")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body.Load().(string))) }))
	defer server.Close()
	dir := t.TempDir()
	policy := Policy{Assets: []Asset{{URL: server.URL, File: "geosite.dat"}}}
	prepare := func(base, value string) string {
		t.Helper()
		body.Store(value)
		target, err := Prepare(context.Background(), base, policy, nil, server.Client(), true)
		if err != nil {
			t.Fatal(err)
		}
		return target
	}
	first := prepare(dir, "first")
	if err := Activate(dir, first); err != nil {
		t.Fatal(err)
	}
	second := prepare(dir, "second")
	if err := Activate(dir, second); err != nil {
		t.Fatal(err)
	}
	obsolete := filepath.Join(dir, strings.Repeat("e", 64))
	if err := os.Mkdir(obsolete, 0700); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(dir, ".assets-refresh-fixture")
	candidate := prepare(private, "third")
	published, err := AdoptPrepared(dir, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if published != filepath.Join(dir, filepath.Base(candidate)) || Resolve(dir) != second {
		t.Fatal("publication changed the serving generation before activation")
	}
	for path, expected := range map[string]string{first: "first", second: "second", published: "third"} {
		content, err := os.ReadFile(filepath.Join(path, "geosite.dat"))
		if err != nil || string(content) != expected {
			t.Fatal("publication lost serving, rollback or candidate bytes", path, err)
		}
	}
	if _, err := os.Stat(obsolete); !os.IsNotExist(err) {
		t.Fatal("unreferenced generation was not retired", err)
	}
}

func TestPrivateAssetPublicationPreservesUncertainRecoveryEvidence(t *testing.T) {
	dir := t.TempDir()
	candidate := filepath.Join(t.TempDir(), strings.Repeat("a", 64))
	if err := os.Mkdir(candidate, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "active.json"), []byte("unverifiable"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AdoptPrepared(dir, candidate); err == nil {
		t.Fatal("uncertain active references allowed new publication/cleanup")
	}
	if _, err := os.Stat(candidate); err != nil {
		t.Fatal("refused publication moved the candidate", err)
	}
}
