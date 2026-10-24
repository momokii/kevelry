# Overview aggregates

Site view covered: overview publication-volume charts with date basis, unknown
bucket, correction notes, and source freshness.

## Endpoints

    GET /api/v1/overview

`bucket` is `day` or `month` (default `month`); `months` selects the trailing
bucket count (1–120, default 24). Buckets count current `PUBLISHED` records by
publication timestamp in UTC — never by the year encoded in the ID.

## Example

```bash
curl "https://radar.example.org/api/v1/overview?bucket=month&months=2"
```

```json
{
  "bucket": "month",
  "dateBasis": "publishedAt-utc",
  "buckets": [
    { "bucketStart": "2026-09", "count": 4610 },
    { "bucketStart": "2026-10", "count": 4821 }
  ],
  "unknownDateCount": 37,
  "correctionNotes": ["Cohort 2024-11 annotated per upstream date-issue note."],
  "coverage": {
    "eligibleCohort": 312040,
    "returned": 2,
    "unscored": 41210,
    "unknownEpss": 1804,
    "unknownDate": 37
  },
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

Charts are retrospective counts under the accepted current records:
corrections and rejections can move history, and the move is annotated rather
than hidden. Records with missing publication dates are excluded from dated
buckets and reported as `unknownDateCount` with coverage. Every response
carries `provenance` and the rate-limit headers from the
[README](README.md#limits).
