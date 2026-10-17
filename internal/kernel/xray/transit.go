package xray

import (
	"encoding/json"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func transitAccounts(proto, tag string, settings map[string]any, owner protocol.User, epoch string) ([]any, error) {
	var accounts []any
	for _, binding := range owner.TransitCredentials {
		if binding.InboundTag != tag {
			continue
		}
		user := protocol.Clone(owner)
		user.UUID = ""
		user.Credentials = map[string]json.RawMessage{tag: binding.Credential}
		account, err := accountFor(proto, tag, settings, user)
		if err != nil {
			return nil, err
		}
		account["email"] = protocol.TransitEmail(owner.ID, binding) + "@" + epoch
		if proto == "socks" || proto == "mixed" || proto == "http" {
			account["user"] = account["email"]
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}
