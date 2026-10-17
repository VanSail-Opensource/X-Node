package agent

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func extensionRequirements(config protocol.Config) map[string]bool {
	required := map[string]bool{}
	if config.Firewall.MasterControlled {
		required["firewall_control_v1"] = true
	}
	if config.DNS.Redirect {
		required["xray_scoped_dns_v1"] = true
	}
	if tags, err := protocol.AuxiliaryInboundTags(config.Xray); err == nil && len(tags) > 0 {
		required["native_auxiliary_inbounds_v1"] = true
	}
	if len(config.MemberOutbounds) > 0 {
		required["member_outbound_guards"] = true
	}
	for _, user := range config.Users {
		if user.AccountingPeriod != "" {
			required["traffic_periods_v1"] = true
		}
		if user.ValidUntil != nil {
			required["authorization_expiry"] = true
		}
	}
	return required
}

func adoptsManagedExtensions(next, previous protocol.Config) bool {
	old := extensionRequirements(previous)
	for key := range extensionRequirements(next) {
		if !old[key] {
			return true
		}
	}
	return false
}
