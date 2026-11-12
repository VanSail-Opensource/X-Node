# Peer speed measurements

`Run` accepts a native peer outbound, HTTPS download/upload endpoints, a bounded
transfer (1 KiB to 64 MiB) and 1-120 second timeout. It builds one isolated Xray
client, measures request latency plus download/upload throughput, then closes
that runtime. Results are transient; the existing utility executor owns queuing.

Initial endpoints validate before proxy creation. Every HEAD, GET and POST uses
`httpguard.ExactOrigin`, preserving configured TLS trust and preventing a
redirect from expanding the endpoint's authority. No GitHub CDN exception is
granted to speed tests. `security_test.go` covers invalid endpoint admission;
shared guard regressions cover redirect behavior. No new persistence or library
is introduced. See `docs/http-redirects.md` for policy and extension constraints.
The shared outbound-only client validates effective XHTTP HTTP/2 and download
settings before native construction, matching serving-runtime admission.
