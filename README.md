# caddy-hansestack

Official [Caddy v2](https://caddyserver.com) plugin for
[Hansestack](https://hansestack.de) — B2B k-anonymity password leak checking.

`caddy-hansestack` sits in the request path in front of your existing
backend and asks the Hansestack Leak-Check API whether a submitted password
appears in a known data-breach corpus, then enriches the request/response
with the result. **Zero-code integration**: your backend never has to import
a client library, call an API, or change a single line of code.

> Looking for this project on GitHub? It's tagged with the topic
> [`caddy-module`](https://github.com/topics/caddy-module), alongside the
> rest of the Caddy plugin ecosystem.

## How it works

1. The plugin inspects the request body (JSON or form-encoded) for a
   configurable password field.
2. If found, it asks the Hansestack Leak-Check API — via the official
   [`hansestack-go`](https://github.com/hansestack/hansestack-go) client —
   whether that password is known to be leaked, using k-anonymity so the
   plaintext password never leaves your infrastructure's process boundary
   in identifiable form.
3. Depending on the configured `mode`, it either enriches the outgoing
   request headers, enriches the response headers, or blocks the request
   outright with a 4xx.

The original request body is always restored byte-for-byte before your
backend sees it — the plugin only *observes* the password field, it never
withholds or mutates the body your application receives.

## Fail-Open by Design

Hansestack is a supplementary security signal, never a single point of
failure. If the Leak-Check API is slow, rate-limited, or unreachable, the
plugin **always** lets the request through unmodified (except in `mode:
block`, where only a *confirmed* leak — never an error or timeout — blocks
the request). Every failure mode is logged via Caddy's native `*zap.Logger`
so operators see it, but end users are never affected.

## Requirements

- Go 1.22+ (for building from source)
- A Hansestack API key ([hansestack.de](https://hansestack.de))

## Installation

### Option A: Build with `xcaddy` (recommended)

```sh
xcaddy build --with github.com/hansestack/caddy-hansestack
```

### Option B: Docker Compose with the pre-built GHCR image (easiest)

No Go toolchain, no `xcaddy`, no local build — just the pre-built image and
a Caddyfile:

```sh
git clone https://github.com/hansestack/caddy-hansestack.git
cd caddy-hansestack
cp .env.skel .env
# then edit .env and set HANSESTACK_API_KEY to your real API key
docker compose up -d
```

This pulls `ghcr.io/hansestack/caddy-hansestack:latest` and starts:

- `caddy` — the official pre-built Caddy binary with the Hansestack plugin,
  listening on `localhost:8080`
- `dummy-backend` — a [`traefik/whoami`](https://hub.docker.com/r/traefik/whoami)
  container standing in for your real backend, completely unaware that
  Hansestack is in front of it

For production, pin an explicit version instead of floating on `:latest` —
see [Releasing & Versioning](#releasing--versioning) below — and for local
plugin development, `docker-compose.yml` has a commented-out `build: .` line
you can swap in instead of the `image:`/`pull_policy:` lines.

Then try it out:

```sh
curl -i -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password"}'
```

Look for the `X-Hansestack-Leaked` and `X-Hansestack-Leak-Count` headers in
the response.

## Caddyfile Configuration

```caddyfile
hansestack leakcheck {
    api_key {$HANSESTACK_API_KEY}
    mode enrich_response        # modes: enrich_request | enrich_response | block (default: enrich_request)
    password_field "password"   # key in JSON or form-data (default: "password")
    header_leaked "X-Hansestack-Leaked"       # (default)
    header_count "X-Hansestack-Leak-Count"    # (default)
    block_status 401            # only used if mode=block (default: 401)

    # Optional tuning of the underlying hansestack-go client. Leave these
    # unset to keep the library's own defaults.
    timeout 500ms                        # per-request timeout (default: 500ms)
    circuit_breaker_threshold 5          # consecutive failures before tripping (default: disabled)
    circuit_breaker_cooldown 30s         # how long the circuit stays open (default: 30s)
}
```

| Directive                    | Default                    | Description                                                             |
| ---------------------------- | -------------------------- | ------------------------------------------------------------------------|
| `api_key`                    | *(required)*                | Your Hansestack API key. Use `{$ENV_VAR}` to inject it via environment. |
| `mode`                       | `enrich_request`            | One of `enrich_request`, `enrich_response`, `block`.                    |
| `password_field`             | `password`                  | JSON key / form field name that carries the plaintext password.        |
| `header_leaked`              | `X-Hansestack-Leaked`       | Header set to `true`/`false` once the check completes.                 |
| `header_count`               | `X-Hansestack-Leak-Count`   | Header set to the number of breaches the password was found in.        |
| `block_status`               | `401`                       | HTTP status returned when `mode=block` and a leak is confirmed.        |
| `timeout`                    | `500ms`                     | Per-request timeout against the Leak-Check API (any Caddy duration string, e.g. `500ms`, `1s`). A leak check must never become a latency bottleneck in an auth flow, so keep this small. |
| `circuit_breaker_threshold`  | *(disabled)*                 | Number of consecutive check failures (timeouts, connection errors, 5xx, 429) after which the client stops sending requests and fails open immediately until the cooldown elapses. `0` or unset disables the breaker. |
| `circuit_breaker_cooldown`   | `30s`                        | How long the circuit stays open before a single probe request is let through again. Only takes effect if `circuit_breaker_threshold` is set. |

Both `timeout` and the circuit breaker only ever change *how fast* a fail-open
skip happens — they never turn a skip into a rejected request. See
[Fail-Open by Design](#fail-open-by-design) above and
[Metrics](#metrics) below for how to observe skipped checks.

### Directive Order

`hansestack` registers itself to always run **before** `reverse_proxy` in
Caddy's directive order, so you can write it directly inside a site block —
no `order` global option or `route { }` block required:

```caddyfile
:80 {
    hansestack leakcheck {
        api_key {$HANSESTACK_API_KEY}
    }
    reverse_proxy backend:8080
}
```

If you ever combine `hansestack` with other third-party plugins that also
define their own directive order relative to `reverse_proxy`, and you need
finer control over exactly where `hansestack` runs relative to *those*
plugins, you can still override the position explicitly, either with the
`order` global option:

```caddyfile
{
    order hansestack before basic_auth
}
```

or by placing it inside a `route { }` block, which preserves the exact order
you write, ignoring Caddy's sorting rules entirely:

```caddyfile
route {
    hansestack leakcheck { ... }
    reverse_proxy backend:8080
}
```

### Operation Modes

**`enrich_response` is the recommended default.** It only ever sets headers
— it never rejects a request, never changes a status code, and never adds
latency. Reach for `block` only when you have explicitly decided that your
auth flow must reject known-leaked passwords outright; that is a product
decision your team should make on purpose, not a side effect of installing
this plugin.

- **`enrich_response`** (asynchronous, default-recommended): starts the leak
  check concurrently with the downstream handler chain, then blocks only the
  outgoing `WriteHeader` call — for the duration of the (500ms-bounded) API
  call at most — to inject `header_leaked`/`header_count` into the
  *response* before it is sent to the client. This adds effectively zero
  latency if your backend takes longer than the leak check to respond, and
  nothing is ever blocked: your login endpoint's behavior is completely
  unchanged, just observed.
- **`enrich_request`** (synchronous): waits for the API result, then injects
  the same headers into the *request* instead, before calling the next
  handler. Useful if your backend itself wants to branch on the result
  server-side (e.g. to show a "please change your password" notice). Also
  never blocks anything by itself — it only adds headers your application
  can choose to read or ignore.
- **`block`** (synchronous — the only mode that can reject a request):
  waits for the API result. If, and only if, the API affirmatively confirms
  `leaked == true`, the request is short-circuited with `block_status` and a
  generic JSON error body — your backend is never invoked. Any other
  outcome (not leaked, timeout, rate-limited, API error) passes the request
  through untouched. Choose this deliberately, and confirm with whoever owns
  the auth flow that rejecting known-leaked passwords outright is the
  intended behavior before enabling it in production.

### Scoping to Specific Paths

`hansestack` is registered as a standard Caddy HTTP handler directive, so it
accepts an optional [request matcher](https://caddyserver.com/docs/caddyfile/matchers)
token, exactly like `reverse_proxy` or `header` do. Use this to restrict the
leak check to your actual authentication endpoints, rather than running it
in front of every request the site block handles:

```caddyfile
:80 {
    hansestack /auth/login* leakcheck {
        api_key {$HANSESTACK_API_KEY}
    }
    reverse_proxy backend:8080
}
```

With this in place, requests to `/auth/login*` are inspected as described
above, while every other request (uploads, static assets, unrelated API
calls) reaches `reverse_proxy` directly, without `hansestack` ever touching
the request body. This matters in particular for `multipart/form-data`
(file upload) endpoints elsewhere on the same site: since the plugin checks
the `Content-Type` before reading a single byte of the body, and skips
anything that isn't `application/json` or
`application/x-www-form-urlencoded`, those requests are never buffered by
this plugin regardless of scoping — but scoping to your login/signup/
password-change endpoints is still recommended defense in depth, so the
plugin's code path is only ever exercised where it's actually meant to run.

## Security Notes

- **The `Content-Type` header is checked before a single byte of the body is
  read.** Only `application/json` and `application/x-www-form-urlencoded`
  are ever inspected; any other content type — including
  `multipart/form-data` file uploads — is passed through completely
  untouched. `r.Body` is never wrapped, read, or replaced in that case, so
  large uploads are never buffered into memory just because this plugin is
  installed in front of the endpoint.
- For the two content types that are inspected, the body is read through
  `io.LimitReader` (1 MiB cap) to bound memory usage against oversized or
  malicious payloads. Bodies over the limit are left completely unparsed (no
  password check runs) but are still forwarded to your backend byte-for-byte.
- The plaintext password is only ever handed to the official
  `hansestack-go` client's `CheckPassword` method, in-process, for the
  duration of a single k-anonymity lookup. It is never logged, cached, or
  written to disk by this plugin.
- See [Scoping to Specific Paths](#scoping-to-specific-paths) above for how
  to additionally restrict which routes run through this plugin at all.

## Metrics

If Caddy's [`metrics`](https://caddyserver.com/docs/metrics) global option
is enabled, this plugin exposes its own Prometheus counters on Caddy's
built-in `/metrics` endpoint, under a dedicated `hansestack_leakcheck_*`
namespace (distinct from Caddy's own `caddy_http_*` metrics, since these
describe a Hansestack API outcome, not an HTTP server statistic):

```caddyfile
{
    metrics
}
```

| Metric                                          | Type    | Description                                                                 |
| ----------------------------------------------- | ------- | ---------------------------------------------------------------------------|
| `hansestack_leakcheck_checks_total{result}`     | Counter | Total passwords checked, labeled `result="leaked"` or `result="not_leaked"`.|
| `hansestack_leakcheck_check_outcomes_total{outcome}` | Counter | The *reasoning* behind every check, labeled `outcome="checked"`, `"skipped_timeout"`, `"skipped_rate_limited"`, `"skipped_circuit_open"`, `"skipped_error"`, or `"skipped_canceled"`. Under fail-open, a skipped check and a genuine "not leaked" both count as `result="not_leaked"` above — this metric is what tells them apart. |
| `hansestack_leakcheck_check_errors_total`       | Counter | Total checks that fell back to fail-open because the API client errored. In the default configuration this should stay at zero; a nonzero rate signals a misconfiguration (e.g. an invalid API key) worth investigating, even though no end user was ever affected. |

Example query — leak rate over the last 5 minutes:

```promql
sum(rate(hansestack_leakcheck_checks_total{result="leaked"}[5m]))
/
sum(rate(hansestack_leakcheck_checks_total[5m]))
```

Example query — share of checks that were actually answered by the API
(as opposed to skipped under fail-open) over the last 5 minutes:

```promql
sum(rate(hansestack_leakcheck_check_outcomes_total{outcome="checked"}[5m]))
/
sum(rate(hansestack_leakcheck_check_outcomes_total[5m]))
```

A sustained drop below 1.0 here — especially with a rising
`outcome="skipped_circuit_open"` or `"skipped_timeout"` rate — means the
Leak-Check API is degraded or unreachable; end users are unaffected (every
mode except `block` still passes requests through, and `block` still only
rejects on a *confirmed* leak), but the leak check itself isn't running.

## Releasing & Versioning

Versions follow [SemVer](https://semver.org) via Git tags (`vX.Y.Z`, e.g.
`v1.0.0`). Pushing such a tag triggers `.github/workflows/release.yml`,
which:

1. Re-runs the full quality gate (build, vet, gofmt, `go mod tidy` drift
   check, race-tested unit tests) on the tagged commit.
2. Builds the `Dockerfile` for `linux/amd64` and `linux/arm64`, and pushes it
   to `ghcr.io/hansestack/caddy-hansestack`, tagged with the exact version
   (e.g. `1.0.0`, `1.0`) and moved forward as `latest`.
3. Publishes a GitHub Release with auto-generated release notes.

Consumers can pin either mechanism to a specific version:

```sh
# Docker
image: ghcr.io/hansestack/caddy-hansestack:1.0.0
```

```sh
# xcaddy / go get
xcaddy build --with github.com/hansestack/caddy-hansestack@v1.0.0
```

## Development

```sh
go build ./...
go vet ./...
go test ./... -race -cover
```

A `Makefile` bundles the common local workflows (run `make help` for the
full list):

```sh
make test      # go test -race
make test-cover
make lint      # golangci-lint
make vuln      # govulncheck
make verify    # tidy + lint + test — the full local check before pushing
make up        # docker compose up -d (pulls the published GHCR image)
```

## License

See [LICENSE](./LICENSE).
