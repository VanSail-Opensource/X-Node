package agent

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func managedExtensions(config protocol.Config) bool {
	if len(config.MemberOutbounds) > 0 {
		return true
	}
	for _, user := range config.Users {
		if user.AccountingPeriod != "" || user.ValidUntil != nil {
			return true
		}
	}
	return false
}
