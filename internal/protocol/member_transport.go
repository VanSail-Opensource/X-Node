package protocol

import (
	"encoding/json"
	"errors"
	"strings"
)

// XHTTP can dial an independent download destination with independent socket
// settings. Inspect the same alias/extra selection as the native builder and
// apply the member endpoint and peer-ownership boundary at every nested stream.
func validateMemberTransport(value map[string]any, owned map[string]bool) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return errors.New("invalid member transport")
	}
	var root nativeXHTTPStream
	if json.Unmarshal(raw, &root) != nil {
		return errors.New("invalid member transport")
	}
	for stream := &root; stream != nil; {
		if stream.Address != "" && !PublicProxyAddress(stream.Address) {
			return errors.New("member transport endpoint must be a literal public address")
		}
		for key, raw := range stream.Socket {
			var target string
			if len(stream.Socket) != 1 || !strings.EqualFold(key, "dialerProxy") || json.Unmarshal(raw, &target) != nil || !owned[target] {
				return errors.New("member socket overrides are not permitted")
			}
		}
		settings, err := effectiveNativeXHTTP(stream)
		if err != nil {
			return err
		}
		if settings == nil {
			break
		}
		stream = settings.DownloadSettings
	}
	return nil
}
