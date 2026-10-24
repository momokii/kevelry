# Status and health

Site views covered: methodology and data-status page (sources, notices,
ordering rules, coverage gaps, per-source health) plus liveness.

## Endpoints

    GET /api/v1/status
    GET /api/v1/health

Status is the full freshness report: per-source revisions, dates, retrieval
times, stale flags, eligible cohorts, join coverage, the ranking policy
version, and the required reuse notices. Health is a minimal liveness probe
for load balancers and container healthchecks; it reports `initializing`
until the first accepted snapshot of every core source is published.

## Example

```bash
curl "https://radar.example.org/api/v1/status"
curl "https://radar.example.org/api/v1/health"
```

```json
{
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
  },
  "cohorts": { "published": 312040, "kevListed": 1756, "epssScored": 310236 },
  "joinCoverage": { "unmatchedKev": 12, "unmatchedEpss": 5 },
  "notices": [
    "CVE content reproduced per MITRE CVE Terms of Use.",
    "KEV catalog data under CC0 1.0; third-party links and CISA/DHS marks not covered.",
    "EPSS scores by FIRST.org; attribution retained per services terms."
  ],
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

Health answers `{"status": "ok", "version": "v1", "provenance": {...}}`.
Absence from KEV means not listed in the accepted snapshot, not proof of no
exploitation; unmatched join IDs are reported, never manufactured. Every
response carries `provenance` and the rate-limit headers from the
[README](README.md#limits).
