# Change Radar

Site views covered: radar feed and the before/after evidence inspector.

## Endpoints

    GET /api/v1/radar

Newest events first. Optional `since` (UTC `YYYY-MM-DD` checkpoint floor),
`kind`, and `cveId` narrow the feed; `cursor` and `limit` paginate.

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
