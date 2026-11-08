package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAPICredentialCannotFollowCrossOriginRedirect(t *testing.T) {
	var reached atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true); w.WriteHeader(204) }))
	defer other.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/private?query-fixture-secret", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	base := origin.Client()
	api := &apiClient{origin: origin.URL, token: "fixture-private-token", http: base}
	err := api.request(context.Background(), "GET", repositoryRoot, nil, nil)
	if err == nil || reached.Load() || base.CheckRedirect != nil || strings.Contains(err.Error(), "fixture") || strings.Contains(err.Error(), origin.URL) {
		t.Fatal("API credentials escaped their origin or an error disclosed private request data")
	}
}

func TestAPIResponseErrorsDoNotDiscloseBodiesOrRequestValues(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "fixture-private-server-body")
	}))
	defer server.Close()
	api := &apiClient{origin: server.URL, token: "fixture-private-token", http: server.Client()}
	err := api.request(context.Background(), "PUT", repositoryRoot+"/environments/release/secrets/RELEASE_MINISIGN_SECRET_KEY", map[string]string{"encrypted_value": "fixture-private-request"}, nil)
	if err == nil || err.Error() != "GitHub API PUT "+repositoryRoot+"/environments/release/secrets/RELEASE_MINISIGN_SECRET_KEY: status 403" {
		t.Fatal("API failure did not remain generic")
	}
}

func TestAPIDecodeRejectsOversizedOrTrailingResponse(t *testing.T) {
	for _, body := range []string{`{} {}`, strings.Repeat(" ", maxAPIBytes) + `{}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		api := &apiClient{origin: server.URL, token: "fixture", http: server.Client()}
		var result map[string]any
		err := api.request(context.Background(), "GET", repositoryRoot, nil, &result)
		server.Close()
		if err == nil {
			t.Fatal("unbounded or trailing API data accepted")
		}
	}
}
