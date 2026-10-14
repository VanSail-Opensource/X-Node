// Package speedtest measures a peer Xray proxy using an isolated outbound-only client.
package speedtest

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Request struct {
	PeerOutbound   json.RawMessage `json:"peer_outbound"`
	DownloadURL    string          `json:"download_url"`
	UploadURL      string          `json:"upload_url"`
	MaxBytes       int64           `json:"max_bytes,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
}
type Result struct {
	LatencyMillis  []float64 `json:"request_latency_millis"`
	DownloadBytes  int64     `json:"download_bytes"`
	UploadBytes    int64     `json:"upload_bytes"`
	DownloadMbps   float64   `json:"download_mbps"`
	UploadMbps     float64   `json:"upload_mbps"`
	DurationMillis int64     `json:"duration_millis"`
}

func Run(ctx context.Context, request Request, progress func(string)) (Result, error) {
	var result Result
	for _, raw := range []string{request.DownloadURL, request.UploadURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return result, errors.New("speedtest endpoints require HTTPS")
		}
	}
	if request.MaxBytes == 0 {
		request.MaxBytes = 32 << 20
	}
	if request.MaxBytes < 1024 || request.MaxBytes > 64<<20 {
		return result, errors.New("invalid speedtest transfer bound")
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = 60
	}
	if request.TimeoutSeconds < 1 || request.TimeoutSeconds > 120 {
		return result, errors.New("invalid speedtest timeout")
	}
	var outbound map[string]any
	if json.Unmarshal(request.PeerOutbound, &outbound) != nil || outbound == nil {
		return result, errors.New("invalid peer outbound")
	}
	if outbound["protocol"] == "freedom" || outbound["protocol"] == "direct" || outbound["protocol"] == "blackhole" {
		return result, errors.New("speedtest requires a peer proxy outbound")
	}
	outbound["tag"] = "probe-peer"
	child, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutSeconds)*time.Second)
	defer cancel()
	client, close, e := xray.HTTPClient(child, []any{outbound}, "probe-peer")
	if e != nil {
		return result, e
	}
	defer close()
	start := time.Now()
	progress("latency")
	for i := 0; i < 3; i++ {
		request, e := http.NewRequestWithContext(child, "HEAD", request.DownloadURL, nil)
		if e != nil {
			return result, e
		}
		at := time.Now()
		response, e := client.Do(request)
		if e != nil {
			return result, errors.New("peer latency probe failed")
		}
		response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return result, errors.New("latency endpoint returned an error")
		}
		result.LatencyMillis = append(result.LatencyMillis, float64(time.Since(at).Microseconds())/1000)
	}
	progress("download")
	get, _ := http.NewRequestWithContext(child, "GET", request.DownloadURL, nil)
	at := time.Now()
	response, e := client.Do(get)
	if e != nil {
		return result, errors.New("peer download failed")
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		return result, errors.New("download endpoint returned an error")
	}
	result.DownloadBytes, e = io.Copy(io.Discard, io.LimitReader(response.Body, request.MaxBytes))
	response.Body.Close()
	if e != nil {
		return result, errors.New("peer download interrupted")
	}
	result.DownloadMbps = float64(result.DownloadBytes) * 8 / time.Since(at).Seconds() / 1e6
	progress("upload")
	uploadBytes := min(request.MaxBytes, int64(8<<20))
	post, _ := http.NewRequestWithContext(child, "POST", request.UploadURL, io.LimitReader(zeroReader{}, uploadBytes))
	post.ContentLength = uploadBytes
	post.Header.Set("Content-Type", "application/octet-stream")
	at = time.Now()
	response, e = client.Do(post)
	if e != nil {
		return result, errors.New("peer upload failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, errors.New("upload endpoint returned an error")
	}
	result.UploadBytes = uploadBytes
	result.UploadMbps = float64(uploadBytes) * 8 / time.Since(at).Seconds() / 1e6
	result.DurationMillis = time.Since(start).Milliseconds()
	return result, nil
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }
