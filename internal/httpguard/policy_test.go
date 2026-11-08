package httpguard

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const releaseURL = "https://github.com/owner/repository/releases/download/v1.2.3/asset.zip"
const cdnURL = "https://release-assets.githubusercontent.com/asset?signature=private"

func TestGitHubCDNExceptionIsNarrowlyScoped(t *testing.T) {
	for _, test := range []struct {
		name, initial, method string
		policy                Policy
		body, allow           bool
	}{
		{"GET asset", releaseURL, http.MethodGet, GitHubDownloads, false, true},
		{"HEAD asset", releaseURL, http.MethodHead, GitHubDownloads, false, true},
		{"latest asset", "https://github.com/owner/repository/releases/latest/download/asset.zip", http.MethodGet, GitHubDownloads, false, true},
		{"explicit port", "https://github.com:443/owner/repository/releases/download/v1.2.3/asset.zip", http.MethodGet, GitHubDownloads, false, true},
		{"ordinary profile", releaseURL, http.MethodGet, ExactOrigin, false, false},
		{"POST", releaseURL, http.MethodPost, GitHubDownloads, true, false},
		{"GET body", releaseURL, http.MethodGet, GitHubDownloads, true, false},
		{"API URL", "https://api.github.com/repos/owner/repository/releases/latest", http.MethodGet, GitHubDownloads, false, false},
		{"other path", "https://github.com/owner/repository/blob/main/asset.zip", http.MethodGet, GitHubDownloads, false, false},
		{"other port", "https://github.com:444/owner/repository/releases/download/tag/asset", http.MethodGet, GitHubDownloads, false, false},
		{"subdomain", "https://child.github.com/owner/repository/releases/download/tag/asset", http.MethodGet, GitHubDownloads, false, false},
		{"host suffix", "https://github.com.other.example/owner/repository/releases/download/tag/asset", http.MethodGet, GitHubDownloads, false, false},
		{"missing asset", "https://github.com/owner/repository/releases/download/tag", http.MethodGet, GitHubDownloads, false, false},
		{"missing latest asset", "https://github.com/owner/repository/releases/latest/download", http.MethodGet, GitHubDownloads, false, false},
		{"other latest path", "https://github.com/owner/repository/releases/latest/other/asset", http.MethodGet, GitHubDownloads, false, false},
		{"path traversal", "https://github.com/owner/repository/releases/download/../asset", http.MethodGet, GitHubDownloads, false, false},
		{"encoded traversal", "https://github.com/owner/repository/releases/download/v1%2F..%2Fother/asset", http.MethodGet, GitHubDownloads, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return mockResponse(request, http.StatusFound, cdnURL), nil
				}
				return mockResponse(request, http.StatusOK, ""), nil
			}}}
			request := requestForTest(t, test.method, test.initial)
			if test.body {
				request.Body = io.NopCloser(strings.NewReader("private"))
				request.ContentLength = 7
			}
			response, err := Do(client, request, test.policy)
			if (err == nil) != test.allow {
				t.Fatalf("unexpected boundary result: %v", err)
			}
			if response != nil {
				response.Body.Close()
			}
			if test.allow && calls != 2 || !test.allow && calls != 1 {
				t.Fatal("unexpected transport reached")
			}
		})
	}
}

func TestCDNChainCannotLeaveApprovedOrigin(t *testing.T) {
	for _, target := range []string{releaseURL, "http://release-assets.githubusercontent.com/asset", "https://release-assets.githubusercontent.com:444/asset", "https://child.release-assets.githubusercontent.com/asset", "https://user:secret@release-assets.githubusercontent.com/asset"} {
		calls := 0
		client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return mockResponse(request, http.StatusFound, cdnURL), nil
			}
			return mockResponse(request, http.StatusFound, target), nil
		}}}
		if _, err := Do(client, requestForTest(t, http.MethodGet, releaseURL), GitHubDownloads); err == nil || calls != 2 {
			t.Fatal("CDN chain left its approved origin")
		}
	}
}

func TestCustomCallbackCannotChangeCDNMethodOrMintEligibility(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		calls := 0
		client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
			calls++
			return mockResponse(request, http.StatusFound, cdnURL), nil
		}}, CheckRedirect: func(next *http.Request, via []*http.Request) error {
			via[0].Method = http.MethodGet
			next.Method = http.MethodPost
			return nil
		}}
		if _, err := Do(client, requestForTest(t, method, releaseURL), GitHubDownloads); err == nil || calls != 1 {
			t.Fatal("callback changed CDN authorization")
		}
	}
}

func TestRedirectBudgetIncludesEveryFollowedHop(t *testing.T) {
	for _, length := range []int{10, 11} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
				calls++
				position, err := strconv.Atoi(strings.TrimPrefix(request.URL.Path, "/"))
				if err != nil {
					t.Fatal(err)
				}
				if position == length {
					return mockResponse(request, http.StatusOK, ""), nil
				}
				return mockResponse(request, http.StatusFound, fmt.Sprintf("/%d", position+1)), nil
			}}}
			response, err := Do(client, requestForTest(t, http.MethodGet, "https://origin.example/0"), ExactOrigin)
			if response != nil {
				response.Body.Close()
			}
			if length == 10 && err != nil || length == 11 && err == nil || calls != 11 {
				t.Fatal("redirect budget was not enforced at ten followed hops")
			}
		})
	}
}
