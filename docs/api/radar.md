# Change Radar

Site views covered: radar feed and the before/after evidence inspector.

## Endpoints

    GET /api/v1/radar
    GET /api/v1/radar/feed.xml

Newest events first. Optional `since` (UTC `YYYY-MM-DD` checkpoint floor),
`kind`, and `cveId` narrow the feed; `cursor` and `limit` paginate the JSON
route. Reads serve accepted local snapshots only; no upstream call is made.

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

### HTTP behaviour

`Content-Type: application/rss+xml; charset=utf-8`. Success responses carry
`Cache-Control` and a strong `ETag` derived from the retained checkpoint set
(newest date, oldest date, count) plus the validated query shape, so a repeat
request with `If-None-Match` revalidates as `304`. The feed uses the shared
rate-limit, concurrency, request-bound, preflight, and security-header guards;
errors stay JSON with the usual error catalog.
