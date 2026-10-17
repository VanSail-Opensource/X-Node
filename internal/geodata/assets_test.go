package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFailurePreservesExistingAssets(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("new")) }))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "geosite.dat")
	_ = os.WriteFile(path, []byte("old"), 0600)
	p := Policy{Assets: []Asset{{URL: server.URL, File: "geosite.dat"}}}
	hash := sha256.Sum256([]byte("different"))
	if e := Ensure(context.Background(), dir, p, map[string]string{"geosite.dat": hex.EncodeToString(hash[:])}, server.Client(), true); e == nil {
		t.Fatal("bad hash accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "old" {
		t.Fatal("valid asset overwritten")
	}
	hash = sha256.Sum256([]byte("new"))
	if e := Ensure(context.Background(), dir, p, map[string]string{"geosite.dat": hex.EncodeToString(hash[:])}, server.Client(), true); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(filepath.Join(Resolve(dir), "geosite.dat"))
	if string(b) != "new" {
		t.Fatal("asset not activated")
	}
}
