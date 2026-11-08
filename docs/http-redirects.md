# Privileged HTTP boundaries

Agent-owned geodata, DDNS discovery, proxy-backed speed tests, release downloads
and Vultr provider calls use `httpguard.Do` at the point of execution. Initial
URLs and every hop require HTTPS, valid authority, and no URL credentials,
fragment or control characters. Ordinary redirects remain within the initial
canonical hostname/effective port, including explicitly configured TLS origins.
The guard restricts origins; it does not claim DNS/public-address pinning.

Geodata and signed release downloads additionally support GitHub's exact
`release-assets.githubusercontent.com:443` download hop from a body-free
GET/HEAD release-download path on `github.com:443`. GitHub API calls, ordinary
DDNS/speed endpoints, other methods and arbitrary CDN hosts do not gain this
exception. Tagged and documented latest-release download paths are supported.
Allowed origin changes discard credential, cookie, API-key, referer,
origin and other nonessential headers, including cookies a jar adds afterward.

The helper clones caller clients/requests, preserving timeouts, transports and
stricter redirect callbacks. It rechecks after callbacks and immediately before
transport I/O. Errors do not reveal signed Location queries or URL credentials.
The lazy asset transport invokes an inner RoundTripper directly, so protection
belongs to the outer geodata request rather than the inner Xray client.
General native Xray HTTP clients keep their existing fixture/integration uses.

Existing queues, contexts, response/body limits, hash/signature validation,
immutable asset generations and DNS publication rules remain authoritative.
Rejected redirects cannot publish a new generation or DDNS address, forward a
provider bearer, or substitute unsigned agent artifacts. No endpoint catalog or
request history is added to persistence.

The credential-free shell installer also limits curl redirects to ten HTTPS
hops and retains its existing pinned Minisign key and signed-manifest checks.

Hosted tests cover same-origin TLS redirects, port/host/subdomain changes,
downgrades, user information, redirect chains, malicious callbacks, jar cookies,
the narrow CDN exception, direct execution validation and consumer integration.
No local automated tests run. Sources: [Go HTTP client behavior](https://pkg.go.dev/net/http)
and [GitHub release assets](https://docs.github.com/en/rest/releases/assets).
