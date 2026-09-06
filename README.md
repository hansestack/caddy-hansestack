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

### Option B: Clone and build the Docker image

```sh
git clone https://github.com/hansestack/caddy-hansestack.git
cd caddy-hansestack
docker compose up --build
```

This starts:

- `caddy` — a custom-built Caddy binary with the Hansestack plugin, listening
  on `localhost:8080`
- `dummy-backend` — a [`traefik/whoami`](https://hub.docker.com/r/traefik/whoami)
  container standing in for your real backend, completely unaware that
  Hansestack is in front of it

Set your API key before starting:

```sh
cp .env.skel .env
# then edit .env and set HANSESTACK_API_KEY to your real API key
docker compose up --build
```

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
}
```

| Directive          | Default                    | Description                                                             |
| ------------------ | -------------------------- | ------------------------------------------------------------------------|
| `api_key`          | *(required)*                | Your Hansestack API key. Use `{$ENV_VAR}` to inject it via environment. |
| `mode`             | `enrich_request`            | One of `enrich_request`, `enrich_response`, `block`.                    |
| `password_field`   | `password`                  | JSON key / form field name that carries the plaintext password.        |
| `header_leaked`    | `X-Hansestack-Leaked`       | Header set to `true`/`false` once the check completes.                 |
| `header_count`     | `X-Hansestack-Leak-Count`   | Header set to the number of breaches the password was found in.        |
| `block_status`     | `401`                       | HTTP status returned when `mode=block` and a leak is confirmed.        |

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

- **`enrich_request`** (synchronous): waits for the API result, then injects
  `header_leaked`/`header_count` into the *request* headers before calling
  the next handler. Useful if your backend itself wants to branch on the
  result.
- **`enrich_response`** (asynchronous): starts the leak check concurrently
  with the downstream handler chain, then blocks only the outgoing
  `WriteHeader` call — for the duration of the (500ms-bounded) API call at
  most — to inject the headers into the *response* before it is sent to the
  client. This adds effectively zero latency if your backend takes longer
  than the leak check to respond.
- **`block`** (synchronous): waits for the API result. If, and only if, the
  API affirmatively confirms `leaked == true`, the request is
  short-circuited with `block_status` and a generic JSON error body — your
  backend is never invoked. Any other outcome (not leaked, timeout,
  rate-limited, API error) passes the request through untouched.

## Security Notes

- The request body is read through `io.LimitReader` (1 MiB cap) before
  parsing, to bound memory usage against oversized or malicious payloads.
  Bodies over the limit are left completely unparsed (no password check
  runs) but are still forwarded to your backend byte-for-byte.
- Only `application/json` and `application/x-www-form-urlencoded` bodies are
  inspected. Any other content type (or a missing one) is passed through
  untouched, without error.
- The plaintext password is only ever handed to the official
  `hansestack-go` client's `CheckPassword` method, in-process, for the
  duration of a single k-anonymity lookup. It is never logged, cached, or
  written to disk by this plugin.

## Development

```sh
go build ./...
go vet ./...
go test ./... -race -cover
```

## License

See [LICENSE](./LICENSE).
