package geodata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedAssetsDoNotReplaceServingGeneration(t *testing.T) {
	value := "old"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(value)) }))
	defer server.Close()
	dir := t.TempDir()
	policy := Policy{Assets: []Asset{{URL: server.URL, File: "geosite.dat"}}}
	if err := Ensure(context.Background(), dir, policy, nil, server.Client(), true); err != nil {
		t.Fatal(err)
	}
	old := Resolve(dir)
	value = "new"
	candidate, err := Prepare(context.Background(), dir, policy, nil, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if Resolve(dir) != old {
		t.Fatal("unvalidated generation replaced serving assets")
	}
	if err = Activate(dir, candidate); err != nil {
		t.Fatal(err)
	}
	if err = Activate(dir, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(old, "geosite.dat")); err != nil {
		t.Fatal("repeat activation deleted rollback assets", err)
	}
}
