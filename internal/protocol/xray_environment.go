package protocol

import (
	"encoding/json"
	"errors"
	"strings"
)

// ValidateXrayEnvironment runs before asset, certificate or native preparation.
// Embedded Xray shares the privileged agent process; arbitrary process options
// are not a configuration surface. Extend this list only after reviewing uses.
func ValidateXrayEnvironment(raw json.RawMessage) error {
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || root == nil {
		return errors.New("invalid Xray document")
	}
	var env map[string]string
	if value := root["env"]; value != nil && json.Unmarshal(value, &env) != nil {
		return errors.New("Xray environment must contain string values")
	}
	if len(env) > 32 {
		return errors.New("too many Xray environment options")
	}
	for key, value := range env {
		switch key {
		case "XRAY_LOCATION_ASSET", "XRAY_LOCATION_CERT", "XRAY_LOCATION_CONFIG", "XRAY_LOCATION_CONFDIR",
			"XRAY_JSON_STRICT", "XRAY_BUF_READV", "XRAY_BUF_SPLICE", "XRAY_VMESS_PADDING",
			"XRAY_CONE_DISABLED", "XRAY_RAY_BUFFER_SIZE", "XRAY_BROWSER_DIALER", "XRAY_XUDP_SHOW",
			"XRAY_XUDP_BASEKEY", "XRAY_TUN_FD":
		default:
			return errors.New("unsupported Xray environment option")
		}
		if len(value) > 4096 || strings.ContainsRune(value, '\x00') {
			return errors.New("invalid Xray environment value")
		}
	}
	return nil
}
