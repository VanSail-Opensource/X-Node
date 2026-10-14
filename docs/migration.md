# Migration from Xboard-Node

This is a new control-plane contract. Existing Xboard, Hiddify, node/machine IDs, REST endpoints, local standalone users and multi-instance YAML are removed.

1. Implement the documented master WSS endpoint and persist monotonic agent revisions.
2. Convert listeners into native Xray inbounds with stable tags. Remove native account arrays; send users and eligibility separately.
3. Convert sing-box-only protocols/settings to protocols supported by the pinned Xray core. Unsupported managed inbound protocols fail validation.
4. Move certificate/provider credentials, routing, DNS, telemetry intervals and limits into remote configuration.
5. Install the Debian binary service and provide only connection bootstrap locally.
6. Deduplicate traffic batch IDs and acknowledge them. Replace current online snapshots and send per-user `block_new` decisions.

Preserve the generated agent identity and private state when upgrading. Removing that state creates a new identity and loses locally pending traffic. Credential rotation is authoritative even when an unrelated native configuration fails; send a corrected snapshot with a higher revision.

Firewall ownership is complete. Configure allowed services/forwarding explicitly, then confirm the apply transaction over WSS. SmartDNS is optional; Xray DNS is the default resolver mode.
