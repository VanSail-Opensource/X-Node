// Package geodata owns verified asset downloads and their single refresh schedule.
package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"github.com/robfig/cron/v3"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
	Cron     string  `json:"cron,omitempty"`
	Outbound string  `json:"outbound,omitempty"`
	Assets   []Asset `json:"assets"`
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
	if p.Cron != "" {
		if _, e := cron.ParseStandard(p.Cron); e != nil {
			return p, errors.New("invalid geodata cron")
		}
	}
	seen := map[string]bool{}
	for _, a := range p.Assets {
		u, e := url.Parse(a.URL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !assetName(a.File) || seen[a.File] {
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
	if p.Cron == "" {
		return time.Time{}
	}
	s, e := cron.ParseStandard(p.Cron)
	if e != nil {
		return time.Time{}
	}
	return s.Next(now)
}

// Resolve returns one immutable generation so a runtime never sees a mixed GeoIP/GeoSite pair.
func Resolve(dir string) string {
	b, e := os.ReadFile(filepath.Join(dir, "active.json"))
	if e != nil {
		return dir
	}
	var data struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(b, &data) != nil || len(data.Generation) != 64 {
		return dir
	}
	if _, e = hex.DecodeString(data.Generation); e != nil {
		return dir
	}
	return filepath.Join(dir, data.Generation)
}
func Ensure(ctx context.Context, dir string, p Policy, hashes map[string]string, client *http.Client, refresh bool) error {
	if len(p.Assets) == 0 {
		return nil
	}
	if len(p.Assets) > 32 {
		return errors.New("too many assets")
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	previous := Resolve(dir)
	stage, e := os.MkdirTemp(dir, ".assets-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	actual := map[string]string{}
	var total int64
	for _, a := range p.Assets {
		if !assetName(a.File) {
			return errors.New("invalid asset filename")
		}
		expected := strings.ToLower(hashes[a.File])
		if expected != "" {
			h, e := hex.DecodeString(expected)
			if e != nil || len(h) != 32 {
				return errors.New("invalid asset SHA-256")
			}
		}
		var reader io.ReadCloser
		if !refresh {
			if file, e := os.Open(filepath.Join(previous, a.File)); e == nil {
				digest, e := fileDigest(file)
				file.Close()
				if e == nil && (expected == "" || digest == expected) {
					reader, e = os.Open(filepath.Join(previous, a.File))
					if e != nil {
						return e
					}
				}
			}
		}
		if reader == nil {
			request, e := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
			if e != nil {
				return errors.New("invalid asset URL")
			}
			response, e := client.Do(request)
			if e != nil {
				return errors.New("asset download failed")
			}
			if response.StatusCode != 200 {
				response.Body.Close()
				return errors.New("asset endpoint returned an error")
			}
			reader = response.Body
		}
		file, e := os.OpenFile(filepath.Join(stage, a.File), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			reader.Close()
			return e
		}
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(file, h), io.LimitReader(reader, MaxAssetBytes+1))
		reader.Close()
		syncErr := file.Sync()
		closeErr := file.Close()
		if e != nil || syncErr != nil || closeErr != nil || n <= 0 || n > MaxAssetBytes {
			return errors.New("invalid asset transfer")
		}
		total += n
		if total > MaxGroupBytes {
			return errors.New("asset group exceeds capacity")
		}
		digest := hex.EncodeToString(h.Sum(nil))
		if expected != "" && digest != expected {
			return errors.New("asset SHA-256 mismatch")
		}
		actual[a.File] = digest
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	names := make([]string, 0, len(actual))
	for name := range actual {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		fmt.Fprintf(hash, "%s:%s\n", name, actual[name])
	}
	generation := hex.EncodeToString(hash.Sum(nil))
	target := filepath.Join(dir, generation)
	if _, e = os.Stat(target); os.IsNotExist(e) {
		if e = os.Rename(stage, target); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	pointer, _ := json.Marshal(map[string]string{"generation": generation})
	if e = state.AtomicWrite(filepath.Join(dir, "active.json"), pointer, 0600); e != nil {
		return e
	}
	// Keep the active and immediately previous generations for configuration rollback.
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 64 {
			continue
		}
		if _, e = hex.DecodeString(entry.Name()); e != nil {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if path != target && path != previous {
			if e = os.RemoveAll(path); e != nil {
				return e
			}
		}
	}
	return nil
}
func fileDigest(file *os.File) (string, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(file, MaxAssetBytes+1))
	if e != nil || n <= 0 || n > MaxAssetBytes {
		return "", errors.New("invalid cached asset")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
