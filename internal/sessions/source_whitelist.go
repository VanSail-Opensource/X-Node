package sessions

import (
	"slices"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func sourceAllowed(user protocol.User, ip string) bool {
	return !user.WhitelistEnabled || slices.Contains(user.WhitelistedIPs, ip)
}
