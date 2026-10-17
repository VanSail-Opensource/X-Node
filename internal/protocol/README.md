# Module

`firewall.go` defines configurable rules, authoritative restrictions, exact-IP
exemptions, compact source generations and versioned updates. `firewall_state.go`
defines live status. The `firewall_control_v1` capability and `master_controlled`
policy flag negotiate reports; no detector is authorized to create a blacklist.
