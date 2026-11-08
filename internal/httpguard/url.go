package httpguard

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var errURL = errors.New("HTTP request requires a valid absolute HTTPS URL without credentials or fragments")

// HTTPSURL validates an operator-owned HTTPS endpoint without resolving DNS.
// Explicit private and loopback origins are supported; redirects cannot expand
// that authority. Errors never include a URL or its potentially secret query.
func HTTPSURL(raw string) (*url.URL, error) {
	if raw == "" || strings.Contains(raw, "#") || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return nil, errURL
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return nil, errURL
	}
	query, err := url.QueryUnescape(u.RawQuery)
	if err != nil || strings.IndexFunc(u.Path+query+u.Hostname(), unicode.IsControl) >= 0 || strings.HasSuffix(u.Host, ":") {
		return nil, errURL
	}
	if port := u.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, errURL
		}
	}
	if strings.HasPrefix(u.Host, "[") || strings.Contains(u.Hostname(), ":") {
		address, err := netip.ParseAddr(u.Hostname())
		if err != nil || !address.Is6() || !strings.HasPrefix(u.Host, "[") {
			return nil, errURL
		}
	}
	u.Scheme = "https"
	return u, nil
}

type origin struct{ host, port string }

func urlOrigin(u *url.URL) origin {
	host := strings.ToLower(u.Hostname())
	if address, err := netip.ParseAddr(u.Hostname()); err == nil {
		host = address.String()
	}
	port := u.Port()
	if port == "" {
		port = "443"
	} else if value, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(value)
	}
	return origin{host, port}
}
