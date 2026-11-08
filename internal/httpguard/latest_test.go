package httpguard

import (
	"fmt"
	"net/http"
	"testing"
)

func TestLatestReleaseDownloadKeepsItsNarrowCDNBoundary(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			return mockResponse(request, http.StatusFound, releaseURL), nil
		case 2:
			return mockResponse(request, http.StatusFound, cdnURL), nil
		case 3:
			return mockResponse(request, http.StatusOK, ""), nil
		default:
			return nil, fmt.Errorf("unexpected request")
		}
	}}}
	response, err := Do(client, requestForTest(t, http.MethodGet, "https://github.com/owner/repository/releases/latest/download/asset.zip"), GitHubDownloads)
	if err != nil || calls != 3 {
		t.Fatalf("documented latest download route failed: %v", err)
	}
	response.Body.Close()
}
