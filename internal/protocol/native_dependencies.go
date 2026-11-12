package protocol

import (
	"encoding/json"
	"errors"
)

// NativeOutboundDependencies follows the same case-insensitive fields and
// XHTTP alias/extra selection as the native builder, without opening TLS files.
// Socket penetration replaces the download socket as in the pinned dialer.
func NativeOutboundDependencies(raw json.RawMessage) ([]string, error) {
	var outbound struct {
		Proxy *struct {
			Tag string `json:"tag"`
		} `json:"proxySettings"`
		Stream *nativeXHTTPStream `json:"streamSettings"`
	}
	if json.Unmarshal(raw, &outbound) != nil {
		return nil, errors.New("invalid outbound dependency configuration")
	}
	var dependencies []string
	seen := map[string]bool{}
	add := func(tag string) {
		if tag != "" && !seen[tag] {
			dependencies = append(dependencies, tag)
			seen[tag] = true
		}
	}
	if outbound.Proxy != nil {
		add(outbound.Proxy.Tag)
	}
	type socketOptions struct {
		DialerProxy string `json:"dialerProxy"`
		Penetrate   bool   `json:"penetrate"`
	}
	var inherited *socketOptions
	for stream := outbound.Stream; stream != nil; {
		var socket socketOptions
		if inherited != nil {
			socket = *inherited
		} else {
			value, err := json.Marshal(stream.Socket)
			if err != nil || json.Unmarshal(value, &socket) != nil {
				return nil, errors.New("invalid outbound socket dependency")
			}
		}
		add(socket.DialerProxy)
		settings, err := effectiveNativeXHTTP(stream)
		if err != nil {
			return nil, err
		}
		if settings == nil {
			break
		}
		inherited = nil
		if socket.Penetrate {
			inherited = &socket
		}
		stream = settings.DownloadSettings
	}
	return dependencies, nil
}
