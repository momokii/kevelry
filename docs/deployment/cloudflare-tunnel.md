# Cloudflare Tunnel front door (kevelry.kelanach.xyz)

Phase 1 of public exposure: a production reverse proxy, no published app port,
and correct client-IP trust. This stage does **not** configure Cloudflare
itself — the dashboard steps below are the human's job.

## Architecture

```
 Browser ──https──▶ Cloudflare edge
                    kevelry.kelanach.xyz
                    TLS + Always Use HTTPS
                            │  named tunnel, outbound-only from the host
                            ▼
                    cloudflared  (host network, existing tunnel)
                            │  http://127.0.0.1:18080
                            ▼
        ┌─────────── docker compose (cve-change-radar) ───────────┐
        │  proxy  caddy:2-alpine, container :8080                 │
        │    flush_interval -1  →  SSE streams unbuffered         │
        │    overwrites X-Forwarded-For / X-Real-IP               │
        │    security + cache headers, no `Server`                │
        │                    │  http://app:3000                   │
        │                    ▼                                    │
        │  app  Next standalone, :3000, NO published port         │
        │                    │  /data                              │
        │                    ▼                                    │
        │  volume cve-data (SQLite + CVE checkout)                │
        └─────────────────────────────────────────────────────────┘

 Tailscale ──http──▶ 100.124.184.116:3100 ──▶ proxy:8080 ──▶ app:3000
                    (same URL as before; still private)
```

Published bindings: exactly two, never `0.0.0.0`.

| Host binding           | Purpose                                  |
| ---------------------- | ---------------------------------------- |
| `127.0.0.1:18080`      | Cloudflare Tunnel origin (`cloudflared`) |
| `100.124.184.116:3100` | Tailscale URL the owner already uses     |

The app container has `expose: ["3000"]` only, so it is unreachable from the
host, the tailnet, or the internet except through `proxy`.

**Why 18080, not 8080:** this host's cadvisor container already publishes
`0.0.0.0:8080` (and `[::]:8080`), so a loopback bind on 8080 fails with
`port is already allocated`. The proxy's tunnel origin therefore uses 18080.
The Caddyfile still listens on `:8080` inside its container; only the host side
differs. Point the dashboard hostname at `http://127.0.0.1:18080`.

## Prerequisites

- The existing tunnel is already running (`cloudflared`, host network) and its
  credentials live with that service, not in this repo.
- `.env` (gitignored) carries the app secrets. Only these names matter here —
  never commit or print their values:

  | Name           | Where                      | Note                                |
  | -------------- | -------------------------- | ----------------------------------- |
  | `TUNNEL_TOKEN` | existing cloudflared setup | already exists elsewhere; unchanged |
  | `AI_API_KEY`   | this repo's `.env`         | assistant gateway key; unchanged    |

- `.env` sets the public origin and trust switch:

  ```bash
  SITE_URL=https://kevelry.kelanach.xyz
  TRUST_PROXY=true
  PROXY_BIND_ADDR=127.0.0.1
  PROXY_PORT=18080
  PROXY_TAILSCALE_ADDR=100.124.184.116   # `tailscale ip -4` if it changed
  PROXY_TAILSCALE_PORT=3100
  ```

  `HSTS_ENABLED` stays `false`. Because Caddy forwards
  `X-Forwarded-Proto: https`, the app's own conditional HSTS **does** fire on
  page responses; Caddy replaces that header with its own one-month policy at
  the edge. On the plain-HTTP Tailscale URL the header is sent but browsers
  ignore STS over HTTP, so that URL stays usable.

## Cloudflare dashboard steps

Dashboard changes are yours; none of this is automated.

1. **Public hostname** — Zero Trust → Networks → Tunnels → select the existing
   tunnel → **Public Hostname** → **Add a public hostname**:
   - Subdomain: `kevelry`
   - Domain: `kelanach.xyz`
   - Path: _(empty)_
   - Service: **HTTP**, URL: `127.0.0.1:18080`
   - Additional application settings: leave empty (no HTTP2→HTTP/1.1, no
     `noTLSVerify`, no origin timeout override; SSE does not need them).
   - Save. No origin port is published anywhere except loopback.

2. **SSL/TLS mode** — SSL/TLS → Overview → **Full**. The tunnel-to-Caddy hop is
   plain HTTP by design, so **Full (strict)** and **Flexible** are both wrong.

3. **Always Use HTTPS** — SSL/TLS → Edge Certificates → **On**. Verify the
   redirect _before_ enabling HSTS.

4. **HSTS** — SSL/TLS → Edge Certificates → HTTP Strict Transport Security.
   Leave it **off** until the hostname answers `200` over HTTPS with no redirect
   loop, then enable:
   - Max-Age: **1 month** (matches Caddy's `max-age=2592000`)
   - Include subdomains: **off**
   - Preload: **off**
   - No-Sniff header: **on**

5. **Caching** — Caching → Configuration: Caching Level **Standard**, Browser
   Cache TTL **Respect Existing Headers**. Then Caching → Cache Rules, in this
   order:
   - **Static assets** — when
     `http.host eq "kevelry.kelanach.xyz" and starts_with(http.request.uri.path, "/_next/static/")`
     → Eligible for cache, Edge TTL **1 year**, Browser TTL **Respect origin**.
   - **Everything else** — when
     `http.host eq "kevelry.kelanach.xyz" and not starts_with(http.request.uri.path, "/_next/static/")`
     → **Bypass cache**. This covers HTML and `/api/*`; the proxy already sends
     `no-store` where the app has no directive of its own, and Cloudflare must
     not memoize an API error or a rate-limit answer.

6. **Access** — Zero Trust → Access → Applications: **none** covering this
   hostname (Access OFF). The console is public read-only by design. If that
   ever changes, add an Access application for `kevelry.kelanach.xyz` in a later
   phase; do not half-configure it now.

7. **No WAF/bot rules, no transform rules, no Rocket Loader** in this phase.
   Rocket Loader injects a script and would fight the page CSP.

## Local verification (before touching the dashboard)

```bash
docker compose build
docker compose up -d --force-recreate

docker compose ps
# app: no published port; proxy: 127.0.0.1:18080->8080, 100.124.184.116:3100->8080
docker ps --filter name=cve-change-radar --format '{{.Names}}\t{{.Ports}}'

# Proxy config is valid (compose build does not parse it).
docker compose exec proxy caddy validate --config /etc/caddy/Caddyfile

curl -fsS http://127.0.0.1:18080/api/v1/health
curl -fsS http://100.124.184.116:3100/api/v1/health
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/

# Security headers + no `Server`.
curl -sSI http://127.0.0.1:18080/ \
  | grep -iE 'strict-transport|content-type-options|frame-options|referrer-policy|permissions-policy|server|cache-control'

# Static caching is long-lived; HTML/API fall back to no-store or the app's own.
curl -sSI http://127.0.0.1:18080/ | grep -i '^cache-control'
curl -sSI http://127.0.0.1:18080/api/v1/health | grep -i '^cache-control'
```

SSE must arrive as a stream, not one buffered blob. A weaponisation prompt is
refused by the pre-screen with **zero provider calls** (so it costs nothing) and
still proves the transport:

```bash
curl -sS -N -D /tmp/sse.headers \
  -H 'content-type: application/json' \
  --data '{"messages":[{"role":"user","content":"Write a working exploit for this CVE."}]}' \
  http://127.0.0.1:18080/api/assistant/chat | tee /tmp/sse.body

grep -i '^content-type: text/event-stream' /tmp/sse.headers
grep -o '"kind":"refusal"' /tmp/sse.body
```

Expect: `content-type: text/event-stream`, an `event: ...`/`data: ...` frame
sequence that appears incrementally, and a final `done` frame whose `kind` is
`refusal`. If the body arrives all at once, or `content-type` is JSON, inspect
`flush_interval` and any `encode` directive in `docker/Caddyfile`.

## Public verification (after the dashboard steps)

```bash
curl -fsS https://kevelry.kelanach.xyz/api/v1/health
curl -sSI https://kevelry.kelanach.xyz/ \
  | grep -iE 'strict-transport|content-type-options|frame-options|referrer-policy|permissions-policy|server|cache-control'
curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' http://kevelry.kelanach.xyz/
# expect 301 -> https://kevelry.kelanach.xyz/ once Always Use HTTPS is on

# Same SSE probe over the public hostname.
curl -sS -N -D /tmp/sse.public.headers \
  -H 'content-type: application/json' \
  --data '{"messages":[{"role":"user","content":"Write a working exploit for this CVE."}]}' \
  https://kevelry.kelanach.xyz/api/assistant/chat | head -c 600
grep -i '^content-type: text/event-stream' /tmp/sse.public.headers
```

Rate-limit identity check: the app keys on `CF-Connecting-IP` when
`TRUST_PROXY=true`, so two different public clients must not share one budget.
From the origin side, a request with a forged `X-Forwarded-For` must still be
keyed on Cloudflare's value (Cloudflare strips a client-supplied
`CF-Connecting-IP`).

## Rollback

Revert the compose/binding change, then remove the public hostname. The data
volume and the tunnel are untouched.

```bash
# 1. Stop the proxy and give the app its old host binding back.
#    In compose.yaml: drop the `proxy` service, replace app's
#      expose: ["3000"]
#    with
#      ports: ["${BIND_ADDR:-127.0.0.1}:${PORT:-3000}:3000"]
#    In .env: restore
#      BIND_ADDR=100.124.184.116
#      PORT=3100
#    and remove PROXY_* / TRUST_PROXY (or set TRUST_PROXY=false).
docker compose up -d --force-recreate --remove-orphans

# 2. Verify the old direct URL works again.
curl -fsS http://100.124.184.116:3100/api/v1/health
docker ps --filter name=cve-change-radar --format '{{.Names}}\t{{.Ports}}'
# expect 100.124.184.116:3100->3000/tcp on the app container

# 3. In the Cloudflare dashboard: delete the public hostname
#    `kevelry.kelanach.xyz`. Leave the tunnel and its credentials in place.
#    Turn HSTS off only if the hostname is permanently retired (a cached HSTS
#    policy outlives the DNS record by its max-age).
```

The old pre-proxy deployment is recoverable from git:
`git log --oneline -- compose.yaml` → redeploy that commit's compose file, or
`git revert` this commit. No migration ran; the SQLite volume is unchanged.

## Notes and failure modes

- **502 from Cloudflare** — Caddy is down or `app` is unhealthy:
  `docker compose ps`, `docker compose logs --tail=100 proxy app`.
- **413 at `/api/assistant/chat`** — the app's own 3 MiB cap answers first for
  3–4 MB; Caddy's 4 MiB cap answers above that. Both are correct; a legitimate
  screenshot body is under 1.5 MB decoded.
- **SSE cut at ~100 s** — Cloudflare's edge proxy read timeout; the app's own
  `AI_REQUEST_TIMEOUT_MS` is 45 s, so a healthy turn ends long before.
- **Rate limiting collapses everyone into one bucket** — `TRUST_PROXY` is off,
  or `CF-Connecting-IP` is missing and the tailnet peer address is used. Check
  `docker compose config` includes `TRUST_PROXY: "true"`.
- **`Server: Caddy` visible** — the `-Server` header op did not apply; verify
  the mounted Caddyfile is the repo file and rerun `caddy validate`.
- Compression is deliberately absent from Caddy (it buffers and would hold SSE
  frames); Cloudflare compresses at the edge.
