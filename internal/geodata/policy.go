package geodata

import (
	"encoding/json"
	"errors"
	"github.com/robfig/cron/v3"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const MaxAssetBytes = 128 << 20
const MaxGroupBytes = 256 << 20

type Asset struct {
	URL  string `json:"url"`
	File string `json:"file"`
}
type Policy struct {
	IntervalHours *int    `json:"interval_hours,omitempty"`
	Cron          string  `json:"cron,omitempty"`
	Outbound      string  `json:"outbound,omitempty"`
	Assets        []Asset `json:"assets"`
}

func FromNative(raw json.RawMessage) (Policy, error) {
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return Policy{}, errors.New("invalid Xray config")
	}
	var p Policy
	if len(root["geodata"]) > 0 {
		if json.Unmarshal(root["geodata"], &p) != nil {
			return p, errors.New("invalid GeodataObject")
		}
	}
	if len(p.Assets) > 32 {
		return p, errors.New("too many geodata assets")
	}
	if p.IntervalHours != nil && (*p.IntervalHours < 0 || *p.IntervalHours > 8760) {
		return p, errors.New("invalid geodata hour interval")
	}
	if p.IntervalHours != nil && p.Cron != "" {
		return p, errors.New("geodata interval and legacy cron are mutually exclusive")
	}
	if p.Cron != "" {
		if _, e := cron.ParseStandard(p.Cron); e != nil {
			return p, errors.New("invalid geodata cron")
		}
	}
	seen := map[string]bool{}
	for _, a := range p.Assets {
		u, e := url.Parse(a.URL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || a.File != "geosite.dat" || seen[a.File] {
			return p, errors.New("invalid geodata asset")
		}
		seen[a.File] = true
	}
	return p, nil
}
func assetName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\\x00")
}
func Next(p Policy, now time.Time) time.Time {
	if p.IntervalHours != nil {
		if *p.IntervalHours <= 0 {
			return time.Time{}
		}
		return now.Add(time.Duration(*p.IntervalHours) * time.Hour)
	}
	if p.Cron == "" {
		return time.Time{}
	}
	s, e := cron.ParseStandard(p.Cron)
	if e != nil {
		return time.Time{}
	}
	return s.Next(now)
}
