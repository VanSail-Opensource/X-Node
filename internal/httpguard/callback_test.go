package httpguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCallbackCancellationKeepsClassificationWithoutLeakingDetails(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		calls := 0
		client := &http.Client{Transport: &mockTransport{fn: func(request *http.Request) (*http.Response, error) {
			calls++
			return mockResponse(request, http.StatusFound, "/next"), nil
		}}, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("sensitive callback details: %w", cause) }}
		_, err := Do(client, requestForTest(t, http.MethodGet, "https://approved.example/start"), ExactOrigin)
		if !errors.Is(err, cause) || strings.Contains(err.Error(), "sensitive") || calls != 1 {
			t.Fatal("callback classification or redaction changed")
		}
	}
}
