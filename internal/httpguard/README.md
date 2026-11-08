# Privileged HTTPS origins

`HTTPSURL` validates endpoints without returning raw URLs in errors. Explicit
HTTPS private and loopback origins remain operator-owned configuration. The
guard constrains redirect authority; it does not resolve or pin DNS addresses.

`Do` validates the initial request at execution time, clones the injected client
and request, and applies a ten-redirect budget. The default `ExactOrigin` policy
requires HTTPS and the same canonical hostname/effective port on every hop.
It rejects user information, fragments, malformed ports, controls, and a Host
override that differs from the URL. Existing redirect callbacks can restrict
the request further; validation runs both before and after those callbacks.
The transport is wrapped to validate again before actual I/O.

`GitHubDownloads` permits one additional boundary only for initial body-free
GET/HEAD requests to `https://github.com/<owner>/<repo>/releases/download/...`
or the documented `/releases/latest/download/<asset>` route
at port 443: the exact `release-assets.githubusercontent.com:443` CDN. Once on
that CDN, the chain must stay there. GitHub API URLs, other paths, request bodies,
other methods, subdomains, ports and arbitrary CDN names gain no exception.

Allowed origin changes retain only User-Agent, Accept and the explicit range /
cache-validation headers. Headers and trailers are private copies. Authorization,
cookies, API keys, Referer, Origin and other headers never cross the boundary;
transport-side stripping also handles cookies added by an injected cookie jar.
The caller still owns queueing, context deadlines, TLS trust and transport
cleanup. Errors retain context cancellation/deadline classification without URL
or Location/query details.

Hosted regressions cover TLS redirects, malicious destinations and callbacks,
hop budgets, the precise CDN exception, credential stripping, jar cookies,
request/client isolation and generic errors. No local automated suites run.

References: [Go redirect and header semantics](https://pkg.go.dev/net/http) and
[GitHub release-asset redirects](https://docs.github.com/en/rest/releases/assets).
GitHub also documents [latest-release download links](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases).
