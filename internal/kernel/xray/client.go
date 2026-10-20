package xray

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"net"
	"net/http"
	"time"
)

func HTTPClient(ctx context.Context, outbounds []any, tag string) (*http.Client, func(), error) {
	if err := validateOutbounds(outbounds); err != nil {
		return nil, nil, err
	}
	exists := false
	for _, raw := range outbounds {
		if raw.(map[string]any)["tag"] == tag {
			exists = true
		}
	}
	if !exists {
		return nil, nil, errors.New("unknown probe/download outbound")
	}
	root := map[string]any{"log": map[string]any{"loglevel": "none", "access": "none", "error": "none"}, "outbounds": outbounds, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": tag}}}}
	pb, e := prepareClient(root)
	if e != nil {
		return nil, nil, errors.New("invalid client outbound")
	}
	inst, e := core.NewWithContext(ctx, pb)
	nlog.RestoreXray()
	if e != nil {
		return nil, nil, errors.New("client initialization failed")
	}
	if e = inst.Start(); e != nil {
		_ = inst.Close()
		nlog.RestoreXray()
		return nil, nil, errors.New("client startup failed")
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		p, e := net.LookupPort("tcp", port)
		if e != nil {
			return nil, e
		}
		return core.Dial(ctx, inst, xnet.Destination{Network: xnet.Network_TCP, Address: xnet.ParseAddress(host), Port: xnet.Port(p)})
	}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	cleanup := func() { transport.CloseIdleConnections(); _ = inst.Close(); nlog.RestoreXray() }
	return client, cleanup, nil
}
func DownloadClient(ctx context.Context, raw json.RawMessage, tag string) (*http.Client, func(), error) {
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil {
		return nil, nil, errors.New("invalid download config")
	}
	outbounds, _ := root["outbounds"].([]any)
	return HTTPClient(ctx, outbounds, tag)
}
