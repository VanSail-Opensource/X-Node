// Package geodata owns verified asset downloads and their single refresh schedule.
package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func Prepare(ctx context.Context, dir string, p Policy, hashes map[string]string, client *http.Client, refresh bool) (string, error) {
	if err := pruneAbandonedStages(ctx, dir, time.Now()); err != nil {
		return "", err
	}
	if len(p.Assets) == 0 {
		return Resolve(dir), nil
	}
	if len(p.Assets) > 32 {
		return "", errors.New("too many assets")
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	previous := Resolve(dir)
	stage, e := os.MkdirTemp(dir, ".assets-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(stage)
	actual := map[string]string{}
	var total int64
	for _, a := range p.Assets {
		if !assetName(a.File) || a.File != "geosite.dat" {
			return "", errors.New("invalid asset filename")
		}
		expected := strings.ToLower(hashes[a.File])
		if expected != "" {
			h, e := hex.DecodeString(expected)
			if e != nil || len(h) != 32 {
				return "", errors.New("invalid asset SHA-256")
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
						return "", e
					}
				}
			}
		}
		if reader == nil {
			request, e := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
			if e != nil {
				return "", errors.New("invalid asset URL")
			}
			response, e := client.Do(request)
			if e != nil {
				return "", errors.New("asset download failed")
			}
			if response.StatusCode != 200 {
				response.Body.Close()
				return "", errors.New("asset endpoint returned an error")
			}
			reader = response.Body
		}
		file, e := os.OpenFile(filepath.Join(stage, a.File), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			reader.Close()
			return "", e
		}
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(file, h), io.LimitReader(reader, MaxAssetBytes+1))
		reader.Close()
		syncErr := file.Sync()
		closeErr := file.Close()
		if e != nil || syncErr != nil || closeErr != nil || n <= 0 || n > MaxAssetBytes {
			return "", errors.New("invalid asset transfer")
		}
		total += n
		if total > MaxGroupBytes {
			return "", errors.New("asset group exceeds capacity")
		}
		digest := hex.EncodeToString(h.Sum(nil))
		if expected != "" && digest != expected {
			return "", errors.New("asset SHA-256 mismatch")
		}
		actual[a.File] = digest
	}
	if e = ctx.Err(); e != nil {
		return "", e
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
			return "", e
		}
	} else if e != nil {
		return "", e
	}
	if e = prunePrepared(dir, target); e != nil {
		return "", e
	}
	return target, nil
}
func fileDigest(file *os.File) (string, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(file, MaxAssetBytes+1))
	if e != nil || n <= 0 || n > MaxAssetBytes {
		return "", errors.New("invalid cached asset")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
