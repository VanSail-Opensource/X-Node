package httpguard

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Policy selects the permitted redirect boundary for one request.
type Policy uint8

const (
	// ExactOrigin permits only the initial HTTPS host and effective port.
	ExactOrigin Policy = iota
	// GitHubDownloads additionally permits public GitHub release downloads to
	// the exact release-assets CDN. It never authorizes API or other URL hops.
	GitHubDownloads
)

const maxRedirects = 10

var errRedirect = errors.New("HTTP redirect exceeded its approved HTTPS boundary")
var githubCDN = origin{"release-assets.githubusercontent.com", "443"}

type requestPolicy struct {
	initial origin
	cdn     bool
	usedCDN bool
}

func newRequestPolicy(request *http.Request, policy Policy) requestPolicy {
	initial := urlOrigin(request.URL)
	return requestPolicy{initial: initial, cdn: policy == GitHubDownloads && initial == (origin{"github.com", "443"}) && noBody(request) && readMethod(request.Method) && githubReleasePath(request.URL)}
}

func (p *requestPolicy) authorize(request *http.Request) (origin, error) {
	if request == nil || request.URL == nil {
		return origin{}, errURL
	}
	u, err := HTTPSURL(request.URL.String())
	if err != nil {
		return origin{}, err
	}
	target := urlOrigin(u)
	if request.Host != "" {
		hostURL, err := HTTPSURL((&url.URL{Scheme: "https", Host: request.Host}).String())
		if err != nil || urlOrigin(hostURL) != target || hostURL.Path != "" || hostURL.RawQuery != "" {
			return origin{}, errRedirect
		}
	}
	if target == p.initial && !p.usedCDN {
		return target, nil
	}
	if p.cdn && target == githubCDN && readMethod(request.Method) && noBody(request) {
		return target, nil
	}
	return origin{}, errRedirect
}

func readMethod(method string) bool { return method == http.MethodGet || method == http.MethodHead }

func noBody(request *http.Request) bool {
	return (request.Body == nil || request.Body == http.NoBody) && request.ContentLength <= 0 && len(request.Trailer) == 0
}

func githubReleasePath(u *url.URL) bool {
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(parts) < 6 || parts[2] != "releases" {
		return false
	}
	if parts[3] != "download" && !(parts[3] == "latest" && parts[4] == "download") {
		return false
	}
	for index, raw := range parts {
		part, err := url.PathUnescape(raw)
		if err != nil || part == "" || part == "." || part == ".." {
			return false
		}
		for _, segment := range strings.Split(part, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return false
			}
		}
		if index < 2 && strings.IndexFunc(part, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r))
		}) >= 0 {
			return false
		}
	}
	return true
}

func stripCrossOriginHeaders(request *http.Request) {
	headers := make(http.Header)
	for name, values := range request.Header {
		switch http.CanonicalHeaderKey(name) {
		case "User-Agent", "Accept", "Range", "If-Range", "If-None-Match", "If-Modified-Since":
			headers[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	request.Header = headers
	request.Trailer = nil
}
