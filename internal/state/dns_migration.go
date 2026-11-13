package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Retired DNS fields are accepted only from the bounded private state snapshot.
// New wire input has no resolver mode or inert upstream list. The next ordinary
// state write drops these fields; boot never requires an additional disk write.
func normalizeCachedDNS(raw []byte, data *Data) error {
	if len(raw) == 0 {
		return nil
	}
	type archivedConfig struct {
		DNS struct {
			Mode      string   `json:"mode"`
			Upstreams []string `json:"upstreams"`
		} `json:"dns"`
	}
	var archived struct {
		Config        *archivedConfig `json:"config"`
		DesiredConfig *archivedConfig `json:"desired_config"`
	}
	if err := json.Unmarshal(raw, &archived); err != nil {
		return errors.New("invalid cached DNS configuration")
	}
	for _, entry := range []struct {
		archived *archivedConfig
		current  *protocol.Config
	}{{archived.Config, data.Config}, {archived.DesiredConfig, data.DesiredConfig}} {
		if entry.archived == nil || entry.current == nil {
			continue
		}
		mode := entry.archived.DNS.Mode
		if mode != "" && mode != "xray" && mode != "smartdns" {
			return errors.New("unsupported cached resolver mode")
		}
		if mode == "smartdns" && entry.current.DNS.Redirect {
			if err := preserveCachedLoopback(entry.current); err != nil {
				return fmt.Errorf("cached DNS configuration: %w", err)
			}
		}
	}
	return nil
}

func preserveCachedLoopback(config *protocol.Config) error {
	var root map[string]json.RawMessage
	if json.Unmarshal(config.Xray, &root) != nil || root == nil {
		return errors.New("invalid native configuration")
	}
	var resolver map[string]json.RawMessage
	if raw := bytes.TrimSpace(root["dns"]); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if json.Unmarshal(raw, &resolver) != nil || resolver == nil {
			return errors.New("native DNS must be an object")
		}
	}
	if resolver == nil {
		resolver = map[string]json.RawMessage{}
	}
	var servers []json.RawMessage
	if raw := bytes.TrimSpace(resolver["servers"]); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if json.Unmarshal(raw, &servers) != nil {
			return errors.New("native DNS servers must be an array")
		}
	}
	if len(servers) > 0 {
		return nil
	}
	resolver["servers"] = json.RawMessage(`["127.0.0.1"]`)
	raw, err := json.Marshal(resolver)
	if err != nil {
		return err
	}
	root["dns"] = raw
	config.Xray, err = json.Marshal(root)
	return err
}
