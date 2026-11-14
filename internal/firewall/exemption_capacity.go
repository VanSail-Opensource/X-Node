package firewall

import "errors"

// Immediate deltas share the full-snapshot budget. Removals run after additions,
// matching journal replay; repeated entries cannot hide growth in the projection.
func (g *Guard) admitExemptions(record journalRecord) error {
	count := len(g.state.Exemptions)
	removed := make(map[string]bool, len(record.RemoveExemptions))
	for _, ip := range record.RemoveExemptions {
		if !removed[ip] {
			if _, exists := g.state.Exemptions[ip]; exists {
				count--
			}
		}
		removed[ip] = true
	}
	seen := make(map[string]bool, len(record.Exemptions))
	for _, grant := range record.Exemptions {
		if _, exists := g.state.Exemptions[grant.IP]; !exists && !seen[grant.IP] && !removed[grant.IP] {
			count++
		}
		seen[grant.IP] = true
	}
	// Preserve historical grants above the budget while allowing remediation.
	// Never silently evict paid/manual access to make room for a new grant.
	if count > maxFirewallExemptions && count > len(g.state.Exemptions) {
		return errors.New("firewall exemption capacity exceeded")
	}
	return nil
}
