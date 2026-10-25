// Package dns manages explicit DDNS RRsets and diagnostic resolver probes.
package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/cert/dnsproviders"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/libdns/libdns"
)

type Result struct {
	ID      string    `json:"id"`
	IPv4    string    `json:"ipv4,omitempty"`
	IPv6    string    `json:"ipv6,omitempty"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}
type Setter interface {
	SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error)
}

func Provider(p protocol.Provider) (any, error) {
	builder, ok := dnsproviders.Get(p.Type)
	if !ok {
		return nil, errors.New("unsupported DNS provider")
	}
	return builder.Build(protocol.Clone(p.Credentials))
}
func DDNS(ctx context.Context, j protocol.DDNSJob, p any, client *http.Client) (Result, error) {
	result := Result{ID: j.ID}
	var setter Setter
	if j.Provider != protocol.BuiltinDDNSProvider {
		var ok bool
		setter, ok = p.(Setter)
		if !ok {
			return result, errors.New("provider does not support DDNS record setting")
		}
	}
	v4, err := address(ctx, j.IPv4, j.Interface, j.IPv4URL, true, client)
	if err != nil {
		return result, err
	}
	v6, err := address(ctx, j.IPv6, j.Interface, j.IPv6URL, false, client)
	if err != nil {
		return result, err
	}
	if v4 == "" && v6 == "" {
		return result, errors.New("DDNS job has no address source")
	}
	if j.Provider == protocol.BuiltinDDNSProvider {
		return Result{ID: j.ID, IPv4: v4, IPv6: v6, Updated: time.Now().UTC()}, nil
	}
	zone := strings.TrimSuffix(strings.ToLower(j.Zone), ".") + "."
	absolute := strings.TrimSuffix(strings.ToLower(j.Name), ".")
	zoneName := strings.TrimSuffix(zone, ".")
	if absolute == "@" {
		absolute = zoneName
	}
	if absolute != zoneName && !strings.HasSuffix(absolute, "."+zoneName) {
		return result, errors.New("DDNS name is outside its zone")
	}
	name := libdns.RelativeName(absolute+".", zone)
	if name == "" {
		name = "@"
	}
	if strings.HasSuffix(name, ".") || strings.ContainsAny(name, "\r\n\t ") {
		return result, errors.New("DDNS name is outside its zone")
	}
	ttl := time.Duration(j.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = 300 * time.Second
	}
	records := []libdns.Record{}
	if v4 != "" {
		records = append(records, libdns.RR{Name: name, Type: "A", TTL: ttl, Data: v4})
	}
	if v6 != "" {
		records = append(records, libdns.RR{Name: name, Type: "AAAA", TTL: ttl, Data: v6})
	}
	if _, err = setter.SetRecords(ctx, zone, records); err != nil {
		return result, errors.New("DDNS provider update failed")
	}
	result.IPv4 = v4
	result.IPv6 = v6
	result.Updated = time.Now().UTC()
	return result, nil
}
func address(ctx context.Context, value, iface, lookup string, v4 bool, client *http.Client) (string, error) {
	if value == "" {
		return "", nil
	}
	if value != "auto" {
		a, e := netip.ParseAddr(value)
		if e != nil || a.Unmap().Is4() != v4 || !a.IsGlobalUnicast() {
			return "", errors.New("invalid DDNS address")
		}
		return a.Unmap().String(), nil
	}
	if iface != "" {
		nic, e := net.InterfaceByName(iface)
		if e != nil {
			return "", errors.New("DDNS interface unavailable")
		}
		addrs, e := nic.Addrs()
		if e != nil {
			return "", e
		}
		for _, raw := range addrs {
			p, e := netip.ParsePrefix(raw.String())
			if e == nil && p.Addr().Unmap().Is4() == v4 && p.Addr().IsGlobalUnicast() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
				return p.Addr().Unmap().String(), nil
			}
		}
		return "", errors.New("DDNS interface has no suitable address")
	}
	if lookup == "" {
		return "", errors.New("auto address requires an interface or HTTPS lookup")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, e := http.NewRequestWithContext(ctx, "GET", lookup, nil)
	if e != nil {
		return "", errors.New("invalid DDNS lookup")
	}
	response, e := client.Do(req)
	if e != nil {
		return "", errors.New("DDNS lookup failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("DDNS lookup returned an error")
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 1025))
	if e != nil || len(b) > 1024 {
		return "", errors.New("invalid DDNS lookup response")
	}
	a, e := netip.ParseAddr(strings.TrimSpace(string(b)))
	if e != nil || a.Unmap().Is4() != v4 || !a.IsGlobalUnicast() {
		return "", errors.New("lookup returned the wrong address family")
	}
	return a.Unmap().String(), nil
}
