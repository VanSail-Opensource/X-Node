package httpguard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mockTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return m.fn(request)
}

func mockResponse(request *http.Request, status int, location string) *http.Response {
	headers := make(http.Header)
	if location != "" {
		headers.Set("Location", location)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader("response")), Request: request}
}

func requestForTest(t *testing.T, method, raw string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestExactOriginTLSRedirectPreservesApprovedCredentialsAndClient(t *testing.T) {
	headers := make(chan http.Header, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		headers <- request.Header.Clone()
		if request.URL.Path == "/start" {
			http.Redirect(w, request, "/done", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := server.Client()
	transport := client.Transport
	request := requestForTest(t, http.MethodGet, server.URL+"/start")
	request.Header.Set("Authorization", "Bearer approved-secret")
	response, err := Do(client, request, ExactOrigin)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("same-origin TLS redirect failed")
	}
	for range 2 {
		if (<-headers).Get("Authorization") != "Bearer approved-secret" {
			t.Fatal("approved-origin credential disappeared")
		}
	}
	if client.Transport != transport || client.CheckRedirect != nil || request.URL.Path != "/start" || request.Header.Get("Authorization") != "Bearer approved-secret" {
		t.Fatal("guard mutated an injected client or request")
	}
}

func TestRedirectRejectsEveryUnapprovedBoundary(t *testing.T) {
	for _, location := range []string{
		"https://other.example/path?secret=target-secret", "https://child.origin.example/path",
		"https://origin.example:444/path", "http://origin.example/path", "https://user:password@origin.example/path",
		"https://127.0.0.1/path", "https://[::1]/path", "https://10.0.0.1/path", "https://origin.example/path#fragment",
	} {
		t.Run(location, func(t *testing.T) {
			calls := 0
			transport := &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
				calls++
				return mockResponse(request, http.StatusFound, location), nil
			}}
			request := requestForTest(t, http.MethodGet, "https://origin.example/start?secret=initial-secret")
			_, err := Do(&http.Client{Transport: transport}, request, ExactOrigin)
			if err == nil || calls != 1 {
				t.Fatal("unapproved redirect reached a transport")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "https://") {
				t.Fatal("failure exposed URL data")
			}
		})
	}
}

func TestExistingRedirectCallbackCannotWeakenURLOrHostBoundary(t *testing.T) {
	for _, mutate := range []func(*http.Request, []*http.Request){
		func(next *http.Request, _ []*http.Request) { next.URL.Host = "other.example" },
		func(next *http.Request, _ []*http.Request) { next.Host = "other.example" },
		func(next *http.Request, _ []*http.Request) { next.URL.Scheme = "http" },
		func(next *http.Request, via []*http.Request) {
			via[0].URL.Host = "other.example"
			next.URL.Host = "other.example"
		},
	} {
		calls := 0
		client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
			calls++
			return mockResponse(request, http.StatusFound, "/next"), nil
		}}, CheckRedirect: func(next *http.Request, via []*http.Request) error { mutate(next, via); return nil }}
		if _, err := Do(client, requestForTest(t, http.MethodGet, "https://origin.example/start"), ExactOrigin); err == nil || calls != 1 {
			t.Fatal("callback weakened the origin boundary")
		}
	}
}

func TestExistingRedirectRefusalAndLastResponseRemainEffective(t *testing.T) {
	for _, refusal := range []error{errors.New("https://secret.example/?token=private"), http.ErrUseLastResponse} {
		calls := 0
		client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
			calls++
			return mockResponse(request, http.StatusFound, "/next"), nil
		}}, CheckRedirect: func(*http.Request, []*http.Request) error { return refusal }}
		response, err := Do(client, requestForTest(t, http.MethodGet, "https://origin.example/start"), ExactOrigin)
		if calls != 1 {
			t.Fatal("guard overrode a stricter callback")
		}
		if refusal == http.ErrUseLastResponse {
			if err != nil || response.StatusCode != http.StatusFound {
				t.Fatal("last-response behavior changed")
			}
			response.Body.Close()
		} else if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("callback error was ignored or exposed")
		}
	}
}

func TestCancellationClassificationSurvivesErrorSanitization(t *testing.T) {
	request := requestForTest(t, http.MethodGet, "https://origin.example/?token=private")
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) { return nil, request.Context().Err() }}}
	if _, err := Do(client, request.WithContext(ctx), ExactOrigin); !errors.Is(err, context.Canceled) {
		t.Fatal("context cancellation classification disappeared")
	}
}
