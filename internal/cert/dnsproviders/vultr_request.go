package dnsproviders

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/httpguard"
)

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
	res, e := httpguard.Do(client, req, httpguard.ExactOrigin)
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
