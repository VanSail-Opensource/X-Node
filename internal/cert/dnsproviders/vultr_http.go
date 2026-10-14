package dnsproviders

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/libdns/libdns"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The published libdns Vultr adapter depends on an SDK type removed in current
// govultr. This adapter keeps the supported A/AAAA/TXT REST contract independent of that SDK.
type vultrProvider struct {
	mu     sync.Mutex
	token  string
	client *http.Client
	base   string
}
type vultrRecord struct {
	ID     string
	Record libdns.RR
}

func (r vultrRecord) RR() libdns.RR { return r.Record }

type vultrAPIRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func (p *vultrProvider) request(ctx context.Context, method, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	base := p.base
	if base == "" {
		base = "https://api.vultr.com/v2"
	}
	req, e := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(b))
	if e != nil {
		return errors.New("invalid Vultr request")
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	client := p.client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("Vultr request failed")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("Vultr returned status %d", res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out)
	}
	return nil
}
func vultrPath(zone string) string {
	return "/domains/" + url.PathEscape(strings.TrimSuffix(zone, ".")) + "/records"
}
func (p *vultrProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.get(ctx, zone)
}
func (p *vultrProvider) get(ctx context.Context, zone string) ([]libdns.Record, error) {
	var out []libdns.Record
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		var data struct {
			Records []vultrAPIRecord `json:"records"`
			Meta    struct {
				Links struct {
					Next string `json:"next"`
				} `json:"links"`
			} `json:"meta"`
		}
		path := vultrPath(zone) + "?per_page=500"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		if e := p.request(ctx, "GET", path, nil, &data); e != nil {
			return nil, e
		}
		for _, r := range data.Records {
			out = append(out, vultrRecord{ID: r.ID, Record: libdns.RR{Name: libdns.RelativeName(r.Name, zone), Type: r.Type, Data: r.Data, TTL: time.Duration(r.TTL) * time.Second}})
		}
		if data.Meta.Links.Next == "" {
			return out, nil
		}
		next, e := url.Parse(data.Meta.Links.Next)
		if e != nil {
			return nil, errors.New("invalid Vultr pagination")
		}
		cursor = next.Query().Get("cursor")
		if cursor == "" || seen[cursor] {
			return nil, errors.New("invalid Vultr pagination cursor")
		}
		seen[cursor] = true
	}
	return nil, errors.New("Vultr record limit exceeded")
}
func (p *vultrProvider) append(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var out []libdns.Record
	for _, record := range records {
		r := record.RR()
		if r.Type != "A" && r.Type != "AAAA" && r.Type != "TXT" {
			return nil, errors.New("Vultr adapter manages A, AAAA and TXT only")
		}
		var data struct {
			Record vultrAPIRecord `json:"record"`
		}
		if e := p.request(ctx, "POST", vultrPath(zone), map[string]any{"name": r.Name, "type": r.Type, "data": r.Data, "ttl": int(r.TTL.Seconds())}, &data); e != nil {
			return nil, e
		}
		out = append(out, vultrRecord{ID: data.Record.ID, Record: r})
	}
	return out, nil
}
func (p *vultrProvider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.append(ctx, zone, records)
}
func (p *vultrProvider) delete(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	existing, e := p.get(ctx, zone)
	if e != nil {
		return nil, e
	}
	var out []libdns.Record
	for _, wanted := range records {
		for _, current := range existing {
			a, b := wanted.RR(), current.RR()
			if a.Name == b.Name && a.Type == b.Type && a.Data == b.Data {
				id := current.(vultrRecord).ID
				if e = p.request(ctx, "DELETE", vultrPath(zone)+"/"+url.PathEscape(id), nil, nil); e != nil {
					return nil, e
				}
				out = append(out, current)
			}
		}
	}
	return out, nil
}
func (p *vultrProvider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.delete(ctx, zone, records)
}
func (p *vultrProvider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	existing, e := p.get(ctx, zone)
	if e != nil {
		return nil, e
	}
	var remove, add, result []libdns.Record
	for _, wanted := range records {
		found := false
		for _, current := range existing {
			a, b := wanted.RR(), current.RR()
			if a.Name == b.Name && a.Type == b.Type && a.Data == b.Data {
				found = true
				result = append(result, current)
				if a.TTL != b.TTL {
					if e = p.request(ctx, "PATCH", vultrPath(zone)+"/"+url.PathEscape(current.(vultrRecord).ID), map[string]any{"ttl": int(a.TTL.Seconds())}, nil); e != nil {
						return nil, e
					}
				}
			}
		}
		if !found {
			add = append(add, wanted)
		}
	}
	for _, current := range existing {
		managed, wanted := false, false
		for _, record := range records {
			a, b := record.RR(), current.RR()
			if a.Name == b.Name && a.Type == b.Type {
				managed = true
				if a.Data == b.Data {
					wanted = true
				}
			}
		}
		if managed && !wanted {
			remove = append(remove, current)
		}
	}
	created, e := p.append(ctx, zone, add)
	if e != nil {
		return nil, e
	}
	result = append(result, created...)
	if _, e = p.delete(ctx, zone, remove); e != nil {
		return nil, e
	}
	return result, nil
}
