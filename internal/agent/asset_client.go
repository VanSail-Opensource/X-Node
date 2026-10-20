package agent

import (
	"context"
	"net/http"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type assetTransport struct {
	ctx    context.Context
	config protocol.Config
	tag    string
	client *http.Client
	close  func()
}

// A cached generation never calls RoundTrip, so it never constructs a probe
// core or alters the global system dialer merely to verify cached files.
func lazyAssetClient(ctx context.Context, c protocol.Config, policy geodata.Policy) (*http.Client, func()) {
	if policy.Outbound == "" {
		return nil, func() {}
	}
	t := &assetTransport{ctx: ctx, config: c, tag: policy.Outbound}
	return &http.Client{Transport: t, Timeout: 2 * time.Minute}, func() {
		if t.close != nil {
			t.close()
		}
	}
}

func (t *assetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.client == nil {
		client, close, err := xray.DownloadClient(t.ctx, t.config.Xray, t.tag)
		if err != nil {
			return nil, err
		}
		t.client, t.close = client, close
	}
	return t.client.Transport.RoundTrip(request)
}
