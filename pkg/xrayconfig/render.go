package xrayconfig

import (
	"encoding/json"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/pkg/protocol"
)

// Render returns validated native JSON, including generated managed accounts.
// The returned document contains credentials and must not enter logs or public responses.
func Render(config protocol.Config) (json.RawMessage, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	prepared, err := xray.Prepare(config)
	if err != nil {
		return nil, err
	}
	return json.Marshal(prepared.Native)
}
