// Package httpguard restricts privileged HTTP requests to explicit HTTPS origins.
package httpguard

import (
	"context"
	"errors"
	"net/http"
)

var errRequest = errors.New("guarded HTTPS request failed")

// Do validates the initial request and every redirect without modifying base.
// It preserves the caller's transport, timeout and stricter redirect callbacks.
// Operator-owned initial origins may be private. DNS routing remains the
// transport's responsibility; this helper does not claim public-address pinning.
func Do(base *http.Client, request *http.Request, policy Policy) (*http.Response, error) {
	if request == nil || request.URL == nil || policy != ExactOrigin && policy != GitHubDownloads {
		return nil, errURL
	}
	u, err := HTTPSURL(request.URL.String())
	if err != nil {
		return nil, err
	}
	request = request.Clone(request.Context())
	request.URL = u
	if request.Method == "" {
		request.Method = http.MethodGet
	}
	boundary := newRequestPolicy(request, policy)
	if _, err := boundary.authorize(request); err != nil {
		return nil, err
	}
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	previous := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return errRedirect
		}
		target, err := boundary.authorize(next)
		if err != nil {
			return err
		}
		if target != boundary.initial {
			stripCrossOriginHeaders(next)
		}
		if previous != nil {
			if err := previous(next, via); err != nil {
				if errors.Is(err, http.ErrUseLastResponse) {
					return http.ErrUseLastResponse
				}
				if errors.Is(err, context.Canceled) {
					return context.Canceled
				}
				if errors.Is(err, context.DeadlineExceeded) {
					return context.DeadlineExceeded
				}
				return errRedirect
			}
		}
		target, err = boundary.authorize(next)
		if err != nil {
			return err
		}
		if target != boundary.initial {
			stripCrossOriginHeaders(next)
			boundary.usedCDN = true
		}
		return nil
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = &guardedTransport{base: transport, policy: &boundary}
	response, err := client.Do(request)
	if err != nil {
		// net/http already closes the body before returning redirect errors.
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, errRequest
	}
	return response, nil
}

type guardedTransport struct {
	base   http.RoundTripper
	policy *requestPolicy
}

func (t *guardedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	target, err := t.policy.authorize(request)
	if err != nil {
		return nil, err
	}
	if target != t.policy.initial {
		request = request.Clone(request.Context())
		stripCrossOriginHeaders(request) // The client can add jar cookies after CheckRedirect.
	}
	return t.base.RoundTrip(request)
}
