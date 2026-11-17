# Change Radar

Site views covered: radar feed and the before/after evidence inspector.

## Endpoints

    GET /api/v1/radar
    GET /api/v1/radar/feed.xml
    GET /api/v1/radar/feed.atom

Newest events first. Optional `since` (UTC `YYYY-MM-DD` checkpoint floor),
`kind`, and `cveId` narrow the feed; `cursor` and `limit` paginate the JSON
route. Reads serve accepted local snapshots only; no upstream call is made.

## Subscribe

The radar view carries a `Subscribe` control offering both pull formats side by
side, each a real link with its media type visible and a read-only field that
selects itself on focus so the URL can be copied by keyboard: RSS 2.0
(`type="application/rss+xml"`, `/api/v1/radar/feed.xml`) and Atom 1.0
(`type="application/atom+xml"`, `/api/v1/radar/feed.atom`). Both are the base
feed (no query); add `since`, `kind`, `cveId` or `limit` yourself if you want a
narrower subscription. The control states the one limit that matters: items are
bounded by checkpoint retention.

## Kinds

`kev-added`, `kev-removed`, `cna-changed`, `forecast-changed`, `corrected`,
`rejected`, `list-entered`, `list-exited`, `rank-moved`. Source changes are
distinguished from rank-only, cohort, or window movement: a pure reorder is
labeled `rank-moved` and never presented as a source change. No causal claims
about EPSS internals; KEV dates are catalog-entry dates, not first-exploit
dates.

## Example

```bash
curl "https://radar.example.org/api/v1/radar?since=2026-10-17&kind=kev-added&limit=2"
```

```json
{
  "data": [
    {
      "eventId": "radar-2026-10-23-0001",
      "checkpointDate": "2026-10-23",
      "observedAt": "2026-10-23T04:00:00Z",
      "kind": "kev-added",
      "cveId": "CVE-2026-109618",
      "title": "CVE-2026-109618",
      "changes": [
        { "field": "kev.listed", "before": "false", "after": "true" },
        { "field": "kev.dateAdded", "before": null, "after": "2026-10-23" }
      ],
      "sourceRevision": "kev-2026.10.23",
      "reason": "Added to the accepted KEV catalog on 2026-10-23."
    }
  ],
  "pagination": { "limit": 2, "hasMore": false, "nextCursor": null },
  "provenance": {
    "rankingPolicyVersion": "ranking-v1",
    "generatedAt": "2026-10-24T04:00:00Z",
    "sources": {
      "cve": {
        "revision": "abc1234",
        "lastCheckedAt": "2026-10-24T03:55:00Z",
        "lastAcceptedAt": "2026-10-24T03:10:00Z",
        "stale": false,
        "error": null
      },
      "kev": {
        "catalogVersion": "2026.10.23",
        "lastCheckedAt": "2026-10-24T03:55:00Z",
        "lastAcceptedAt": "2026-10-24T03:10:00Z",
        "stale": false,
        "error": null
      },
      "epss": {
        "scoreDate": "2026-10-23",
        "modelVersion": "v2026.06.15",
        "lastCheckedAt": "2026-10-24T03:55:00Z",
        "lastAcceptedAt": "2026-10-24T03:10:00Z",
        "stale": false,
        "error": null
      }
    }
  }
}
```

Every event names its checkpoint, observation time, and source revision so the
inspector can reproduce the before/after rows. Every response carries
`provenance` and the rate-limit headers from the [README](README.md#limits).

## RSS 2.0 change feed

    GET /api/v1/radar/feed.xml

The same events the JSON route returns, serialized as RSS 2.0 for anonymous
pull subscribers. The feed reuses the JSON route's parsers and filters, so
`since`, `kind`, and `cveId` narrow identically; there is no cursor — the item
count is bounded by `limit` (default 50, max 200). The data comes from accepted
local daily checkpoints, never from a live upstream request.

```bash
curl "https://radar.example.org/api/v1/radar/feed.xml?since=2026-10-17&kind=kev-added&limit=2"
```

### Retention clamp

Checkpoints are retained for 30 UTC days. A `since` older than that window is
rejected with `400 BAD_FILTER`, and the message names the earliest allowed
date. It is never answered with an empty feed, which would read as "no changes"
for a window the service cannot look at.

### Empty feed

When no checkpoint is retained yet (a fresh volume before the daily writer has
run), the feed still answers `200` with a valid, item-less channel, and the
channel `<description>` states that explicitly: "No change checkpoints are
retained yet; this feed fills as the daily checkpoint writer runs." An empty
item list alone would read as "no changes", so the description never says
that. The worker writes at most one checkpoint per UTC date, after a cycle in
which at least one source was accepted.

### Item mapping

| Element                      | Value                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------- |
| `<guid isPermaLink="false">` | `eventId` (stable across re-reads of the same checkpoint)                          |
| `<title>`                    | `<cveId> — <kind>`                                                                 |
| `<pubDate>`                  | RFC 822 timestamp of the checkpoint's `observedAt`                                 |
| `<link>`                     | `https://www.cve.org/CVERecord?id=<cveId>`                                         |
| `<description>`              | `field: before → after` lines, then `reason:`, then `sourceRevision:`, XML-escaped |
| channel `<lastBuildDate>`    | RFC 822 timestamp of the newest retained checkpoint's `observedAt`                 |

Channel title, link, and description state that items come from accepted local
snapshots within the retention window; the channel link points at the JSON
route with the same filters. Items carry no invented narrative: only the
diff's fields, reason, and source revision.

### Absolute links (`SITE_URL`)

`<channel><link>` and `<atom:link rel="self">` must be absolute, so the feed
takes its origin from `SITE_URL` first (trailing slash stripped). On a reverse
proxy without `SITE_URL`, it falls back to `x-forwarded-proto` (default
`https`) plus `x-forwarded-host`, then `host`. The standalone server binds
`0.0.0.0`, so those header values decide whether the links are usable at all:
when the resolved host is `0.0.0.0`, `127.0.0.1`, `localhost`, `::`, or empty —
or `SITE_URL` is not an `http(s)` origin — both links are **omitted on
purpose**. A relative or bind-address link is worse than none: it would send a
subscriber to an address that only exists inside the container. Set `SITE_URL`
on any proxied deployment. Item `<link>` values stay the absolute
`https://www.cve.org/CVERecord?id=<cveId>` URLs regardless.

### HTTP behaviour

`Content-Type: application/rss+xml; charset=utf-8`. Success responses carry
`Cache-Control` and a strong `ETag` derived from the retained checkpoint set
(newest date, oldest date, count) plus the validated query shape, so a repeat
request with `If-None-Match` revalidates as `304`. The feed uses the shared
rate-limit, concurrency, request-bound, preflight, and security-header guards;
errors stay JSON with the usual error catalog.

## Atom 1.0 change feed

    GET /api/v1/radar/feed.atom

The same accepted change events, from the same retained checkpoints, in the same
newest-first order, serialized as Atom 1.0 ([RFC 4287](https://www.rfc-editor.org/rfc/rfc4287.txt)).
It shares the RSS route's query parameters, validation, retention clamp, event
selection, ETag seed, and guards; only the serializer, `Content-Type`, feed path,
and ETag discriminator differ. `since` (UTC `YYYY-MM-DD`), `kind`, and `cveId`
narrow identically, there is no cursor, and `limit` keeps the same bounds
(default 50, max 200). Reads never call upstream.

```bash
curl "https://radar.example.org/api/v1/radar/feed.atom?since=2026-10-17&kind=kev-added&limit=2"
```

### Feed and entry mapping

| Element                        | Value                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| feed `<id>`                    | The feed's own absolute URL (fixed `urn:cve-radar:feed:change-radar` when the public origin is unknown)                   |
| feed `<title>`                 | `CVE Change Radar change feed`                                                                                            |
| feed `<subtitle>`              | The same accepted-snapshot and retention-window provenance text as the RSS `<description>`                                |
| feed `<updated>`               | RFC 3339 form of the newest retained checkpoint's `observedAt`; the retention-window start when no checkpoint is retained |
| feed `<author><name>`          | `Kevelry` — the site, never a person                                                                                      |
| feed `<link rel="self">`       | The Atom URL with the request's canonical filters, `type="application/atom+xml"`                                          |
| feed `<link rel="alternate">`  | The JSON change feed URL with the same filters, `type="application/json"`                                                 |
| entry `<id>`                   | The same `eventId` the RSS `<guid isPermaLink="false">` uses                                                              |
| entry `<title type="text">`    | `<cveId> — <kind>`                                                                                                        |
| entry `<updated>`              | RFC 3339 form of the checkpoint's `observedAt` (never RFC 822)                                                            |
| entry `<summary type="text">`  | `field: before → after` lines, then `reason:`, then `sourceRevision:`, XML-escaped                                        |
| entry `<link rel="alternate">` | `https://www.cve.org/CVERecord?id=<cveId>`                                                                                |

The feed-level `<author>` covers every entry (RFC 4287 §4.1.1), and text
constructs carry `type="text"` (§3.1.1). The entry `<id>` values are the opaque
stable `eventId` strings shared with RSS, kept identical across formats on
purpose; `docs/research/atom-feed.md` records the RFC 4287 §4.2.6 IRI
conformance note behind that choice.

### Retention clamp

The same 30-day checkpoint window applies. A `since` older than it is rejected
with `400 BAD_FILTER`, and the message names the earliest allowed date; it is
never answered with an empty feed. An unpopulated store still answers a valid
Atom document: the `<subtitle>` states that no checkpoints are retained yet, and
`<updated>` is the retention-window start rather than a fabricated freshness.

### HTTP behaviour

`Content-Type: application/atom+xml; charset=utf-8`. Success responses carry the
same `Cache-Control`, strong `ETag` (checkpoint set plus query shape plus the
format discriminator), and `304` revalidation as RSS; a validator minted for one
format does not revalidate the other. The feed uses the shared rate-limit,
concurrency, request-bound, preflight, and security-header guards, and errors
stay JSON with the usual error catalog.

### Absolute links (`SITE_URL`)

Exactly as for RSS: the self and alternate links are absolute and come from
`SITE_URL`, then the proxy headers, then `host`. When the resolved host is
unusable (`0.0.0.0`, loopback, `localhost`, `::`, empty) those links are omitted
on purpose rather than advertising the bind address. Item links stay absolute
`www.cve.org` URLs.
