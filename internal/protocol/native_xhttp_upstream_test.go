package protocol

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func TestXHTTPPureSelectionMatchesPinnedUpstreamBuilder(t *testing.T) {
	for _, raw := range []string{
		`{"network":"xhttp","xhttpSettings":{"h2Params":{"MaxConcurrentStreams":12}}}`,
		`{"network":"splithttp","splithttpSettings":{"h2Params":false},"xhttpSettings":{"h2Params":{}}}`,
		`{"network":"xhttp","xhttpSettings":{"h2Params":false,"extra":{}}}`,
		`{"network":"xhttp","xhttpSettings":{"h2Params":false,"extra":null}}`,
		`{"network":"xhttp","xhttpSettings":{"extra":{"h2Params":{},"extra":{"h2Params":false}}}}`,
		`{"network":"xhttp","xhttpSettings":{"h2Params":{},"extra":{"h2Params":false}}}`,
		`{"network":"xhttp","xhttpSettings":{"downloadSettings":{"network":"xhttp","splithttpSettings":{"h2Params":{}}}}}`,
		`{"network":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"network":"xhttp","xhttpSettings":{"h2Params":false}}}}}`,
		`{"network":"xhttp","xhttpSettings":{"downloadSettings":{"network":"xhttp","xhttpSettings":{"h2Params":false}},"extra":{}}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var local nativeXHTTPStream
			var upstream conf.StreamConfig
			if err := json.Unmarshal([]byte(raw), &local); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(raw), &upstream); err != nil {
				t.Fatal(err)
			}
			built, err := upstream.Build()
			if err != nil {
				t.Fatal(err)
			}
			for selected := &local; selected != nil; {
				effective, err := effectiveNativeXHTTP(selected)
				if err != nil || effective == nil {
					t.Fatal("missing effective local XHTTP", err)
				}
				native := parityXHTTPTransport(t, built)
				if !bytes.Equal(effective.H2Params, native.H2Params) {
					t.Fatal("local HTTP/2 selection differs from native builder")
				}
				selected, built = effective.DownloadSettings, native.DownloadSettings
				if (selected == nil) != (built == nil) {
					t.Fatal("local download selection differs from native builder")
				}
			}
		})
	}
}

func parityXHTTPTransport(t *testing.T, stream *internet.StreamConfig) *splithttp.Config {
	t.Helper()
	for _, transport := range stream.TransportSettings {
		if transport.ProtocolName == "splithttp" {
			instance, err := transport.Settings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			return instance.(*splithttp.Config)
		}
	}
	t.Fatal("missing native XHTTP transport")
	return nil
}
