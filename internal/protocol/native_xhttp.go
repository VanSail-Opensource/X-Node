package protocol

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Keep this pure selection equivalent to the pinned Xray v26.10.31
// conf.StreamConfig.Build and conf.SplitHTTPConfig.Build. Native Build also
// reads TLS files; it cannot run before managed certificate preparation.
type nativeXHTTPStream struct {
	Address   string                     `json:"address"`
	Port      uint16                     `json:"port"`
	Network   string                     `json:"network"`
	Method    *string                    `json:"method"`
	Socket    map[string]json.RawMessage `json:"sockopt"`
	XHTTP     *nativeXHTTPSettings       `json:"xhttpSettings"`
	SplitHTTP *nativeXHTTPSettings       `json:"splithttpSettings"`
}

type nativeXHTTPSettings struct {
	H2Params         json.RawMessage    `json:"h2Params"`
	Extra            json.RawMessage    `json:"extra"`
	DownloadSettings *nativeXHTTPStream `json:"downloadSettings"`
}

func effectiveNativeXHTTP(stream *nativeXHTTPStream) (*nativeXHTTPSettings, error) {
	settings := stream.SplitHTTP
	if stream.XHTTP != nil {
		settings = stream.XHTTP
	}
	if settings == nil || settings.Extra == nil {
		return settings, nil
	}
	// Upstream replaces, rather than merges, extra exactly once. Only Host,
	// Path and Mode survive that replacement; none controls these two fields.
	var extra nativeXHTTPSettings
	if json.Unmarshal(settings.Extra, &extra) != nil {
		return nil, errors.New("invalid XHTTP extra configuration")
	}
	return &extra, nil
}

// validateNativeXHTTP rejects HTTP/2 JSON type errors before Xray opens a
// listener. Upstream defers this unmarshal until after ListenSystem succeeds.
func validateNativeXHTTP(raw json.RawMessage) error {
	type endpoint struct {
		Stream *nativeXHTTPStream `json:"streamSettings"`
	}
	var document struct {
		Inbounds  []endpoint `json:"inbounds"`
		Outbounds []endpoint `json:"outbounds"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return errors.New("invalid XHTTP stream configuration")
	}
	for _, endpoints := range [][]endpoint{document.Inbounds, document.Outbounds} {
		for _, endpoint := range endpoints {
			// Each iteration consumes one nested JSON stream. No recursion,
			// native construction, file access or process mutation occurs here.
			for stream := endpoint.Stream; stream != nil; {
				settings, err := effectiveNativeXHTTP(stream)
				if err != nil {
					return err
				}
				if settings == nil {
					break
				}
				var http2 http.HTTP2Config
				if len(settings.H2Params) > 0 && json.Unmarshal(settings.H2Params, &http2) != nil {
					return errors.New("invalid XHTTP h2Params configuration")
				}
				if download := settings.DownloadSettings; download != nil {
					network := download.Network
					if download.Method != nil {
						network = *download.Method
					}
					// The pinned dialer dereferences Destination and asserts the
					// download protocol is XHTTP after accepting the native build.
					// Reject those unsafe shapes before any listener can start.
					network = strings.ToLower(network)
					if download.Address == "" || download.Port == 0 || network != "xhttp" && network != "splithttp" {
						return errors.New("XHTTP download requires an address, port and XHTTP transport")
					}
				}
				stream = settings.DownloadSettings
			}
		}
	}
	return nil
}
