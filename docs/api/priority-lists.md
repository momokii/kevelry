# Priority lists

Site views covered: known-exploited, highest-forecast, new-critical, and
rising-forecast. Separate signals, deterministic ordering, no invented score.

## Endpoints

    GET /api/v1/priority/{listName}

`{listName}` is one of `known-exploited`, `highest-forecast`, `new-critical`,
`rising-forecast`. Unknown names return `LIST_NOT_FOUND`. Only `cursor` and
`limit` paginate; the cohorts are fixed by the ranking contract.

## Ordering (also returned per response in `ordering`)

- `known-exploited`: KEV `dateAdded` descending, then ID ascending. EPSS is not
  a sort key here.
- `highest-forecast`: known EPSS raw probability descending, known date before
  unknown, publication descending, ID ascending. KEV is not a sort key here.
  Display values are `100 * epss` and `100 * percentile`; a 96th percentile is
  not a 96 percent probability.
- `new-critical`: publication in `[T - 30d, T)` with primary modern CVSS
  >= 9.0, publication descending, ID ascending. Unknown, legacy-only, and
  ADP-only cases are ineligible, not low severity.
- `rising-forecast`: same-model `d` and `d - 7` observations, positive
  `deltaPp = 100 * (epss[d] - epss[d-7])` only; delta descending, current raw
  probability descending, ID ascending. Missing dates and model transitions are
  ineligible, never interpolated. Aligned deltas arrive in `deltaPp`.

## Examples

```bash
curl "https://radar.example.org/api/v1/priority/known-exploited?limit=2"
curl "https://radar.example.org/api/v1/priority/rising-forecast?limit=2"
```

```json
{
  "list": "known-exploited",
  "ordering": ["kev-dateAdded-desc", "cveId-asc"],
  "data": [
    {
      "cveId": "CVE-2026-109618",
      "title": "CVE-2026-109618",
      "state": "PUBLISHED",
      "publishedAt": "2026-10-20T14:02:00Z",
      "officialUrl": "https://www.cve.org/CVERecord?id=CVE-2026-109618",
      "excerpt": "A denial of service flaw was found in the packet parser ...",
      "excerptTruncated": true,
      "excerptLanguage": "en",
      "excerptStatus": "present",
      "kev": { "listed": true, "dateAdded": "2026-10-23" },
      "epss": {
        "status": "known",
        "value": 0.1162,
        "percentile": 0.96047,
        "scoreDate": "2026-10-23",
        "modelVersion": "v2026.06.15"
      },
      "cvssPrimary": {
        "status": "known",
        "source": "cna",
        "version": "4.0",
        "baseScore": 9.2,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      }
    }
  ],
  "deltaPp": null,
  "pagination": { "limit": 50, "hasMore": true, "nextCursor": "W1lOVUYtMjAyNi0xMDk2MTld" },
  "coverage": {
    "eligibleCohort": 1756,
    "returned": 1,
    "unscored": 40,
    "unknownEpss": 12,
    "unknownDate": 0
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

Rising-forecast responses add `deltaPp` aligned with `data` order
(`[8]` means +8 percentage points, computed from exact source decimals, never
rounded display text). Stale snapshots keep dated values with `stale: true`;
they are never relabeled as current. Every response carries `provenance` and
the rate-limit headers from the [README](README.md#limits).
