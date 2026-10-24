# Search

Site view covered: explore and search results (query, filters, excerpts,
official links, missing and language states).

## Endpoints

    GET /api/v1/search

Local FTS-backed search over accepted snapshots only. No nickname index is
promised and no upstream fetch occurs. `q` (2–200 chars) is required; results
mirror the explore view row for row.

## Parameters

`q` plus `cursor`, `limit`, and the shared filters (`severity`, `kev`, `epss`,
`publishedStart`, `publishedEnd`); see [README](README.md#filters).

## Example

```bash
curl "https://radar.example.org/api/v1/search?q=openssl%20denial%20of%20service&limit=2"
```

```json
{
  "q": "openssl denial of service",
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
  "pagination": { "limit": 50, "hasMore": false, "nextCursor": null },
  "coverage": {
    "eligibleCohort": 312040,
    "returned": 1,
    "unscored": 0,
    "unknownEpss": 0,
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

Excerpts are at most 320 Unicode code points plus an ellipsis; `excerptStatus`
is `present`, `fallback-language`, or `not-supplied` (null excerpt). The
official record link is built from the validated ID. Every response carries
`provenance` and the rate-limit headers from the [README](README.md#limits).
