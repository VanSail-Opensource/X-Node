package xray

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"strings"
)

func accountFor(proto, tag string, settings map[string]any, u protocol.User) (map[string]any, error) {
	account := map[string]any{}
	if raw := u.Credentials[tag]; len(raw) > 0 {
		if json.Unmarshal(raw, &account) != nil || account == nil {
			return nil, errors.New("invalid native account")
		}
	}
	switch proto {
	case "vless", "vmess":
		if _, ok := account["id"]; !ok {
			account["id"] = u.UUID
		}
	case "trojan":
		if _, ok := account["password"]; !ok {
			account["password"] = u.UUID
		}
	case "hysteria":
		if _, ok := account["auth"]; !ok {
			account["auth"] = u.UUID
		}
	case "shadowsocks":
		method, _ := settings["method"].(string)
		ss2022 := strings.HasPrefix(method, "2022-")
		if ss2022 {
			if value, exists := account["method"]; exists && value != "" {
				return nil, errors.New("SS2022 user accounts must omit the method")
			}
			delete(account, "method")
		}
		if _, ok := account["password"]; !ok {
			if ss2022 {
				h := sha256.Sum256([]byte(u.UUID))
				size := 32
				if strings.Contains(method, "aes-128") {
					size = 16
				}
				account["password"] = base64.StdEncoding.EncodeToString(h[:size])
			} else {
				account["password"] = u.UUID
			}
		}
		if _, ok := account["method"]; !ok && !ss2022 {
			account["method"] = settings["method"]
		}
	case "socks", "mixed", "http":
		account["user"] = protocol.UserEmail(u, tag)
		if _, ok := account["pass"]; !ok {
			account["pass"] = u.UUID
		}
	}
	account["email"] = protocol.UserEmail(u, tag)
	account["level"] = 0
	return account, nil
}
