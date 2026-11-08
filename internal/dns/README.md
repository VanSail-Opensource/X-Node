# DDNS discovery and DNS utilities

Discovery validates initial lookup URLs at execution and follows only the same
HTTPS origin through `httpguard`. `redirect_test.go` covers port/origin changes
and direct-call validation; failure precedes record publication.

`ddns.go` discovers selected IPv4/IPv6 sources through an interface or configured
HTTPS lookup and preserves family validation and external provider RRset updates.
The reserved `builtin:panel` job returns successful discovered addresses without
provider credentials, zone/name requirements or publishing DNS records. Existing
named providers, including a provider named `builtin`, keep their meaning.

The agent's existing bounded utility executor calls this package; its shared
DDNS coordinator serializes scheduled/manual updates. A failed family discovery
fails the job before publication, leaving the last valid panel addresses intact.
Panel host IDs and binding choices never enter agent discovery configuration.
`builtin_test.go` covers IPv4, IPv6, dual-family discovery, failures and refusal to
call a record setter. Provider implementation construction remains delegated to
the existing libdns registry. Resolver probes keep their existing entry points.
