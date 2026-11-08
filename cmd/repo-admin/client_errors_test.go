package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidationErrorsExposeOnlyBoundedIdentifiersAndOperation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"message":"fixture-private-message","errors":[{"resource":"BranchProtection","field":"required_status_checks.checks","code":"invalid","value":"fixture-private-value","message":"fixture-private-error"},{"field":"unsafe space value","code":"invalid"},"fixture-private-text"]}`))
	}))
	defer server.Close()
	api := &apiClient{origin: server.URL, token: "fixture-private-token", http: server.Client()}
	err := api.request(context.Background(), "PUT", repositoryRoot+"/branches/main/protection?fixture-private-query", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "PUT "+repositoryRoot+"/branches/main/protection: status 422") || !strings.Contains(err.Error(), "resource=BranchProtection field=required_status_checks.checks code=invalid") {
		t.Fatal("validation identifiers or operation were omitted")
	}
	if strings.Contains(err.Error(), "fixture") || strings.Contains(err.Error(), "unsafe") || strings.Contains(err.Error(), server.URL) {
		t.Fatal("validation diagnostic exposed private response or query data")
	}
}

func TestValidationIdentifierBounds(t *testing.T) {
	if got := validationIdentifiers(strings.NewReader(strings.Repeat(" ", 64<<10) + `{}`)); len(got) != 0 {
		t.Fatal("oversized validation body accepted")
	}
	if got := validationIdentifiers(strings.NewReader(`{"errors":[{"field":"` + strings.Repeat("x", 97) + `","code":"invalid"}]}`)); len(got) != 1 || got[0].Field != "" || got[0].Code != "invalid" {
		t.Fatal("unbounded validation identifier accepted")
	}
}
