# CVE records

Site views covered: record rows everywhere a CVE appears (overview entry
points, explore results, priority lists, radar inspector, replay output).

## Endpoints

    GET /api/v1/cves
    GET /api/v1/cves/{cveId}

List returns current `PUBLISHED` records in default-priority order (KEV tier,
EPSS presence, raw probability, date, ID). Detail returns one record with
descriptions, references, and full signals. Rejected IDs are not served here.

## Parameters

List accepts `cursor`, `limit`, and the shared filters (`severity`, `kev`,
`epss`, `publishedStart`, `publishedEnd`); see [README](README.md#filters).
`{cveId}` must match `CVE-YYYY-NNNN+`.

## Example

```bash
curl "https://radar.example.org/api/v1/cves?limit=2&kev=listed"
curl "https://radar.example.org/api/v1/cves/CVE-2026-109618"
```

```json
{
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
  "pagination": { "limit": 50, "hasMore": true, "nextCursor": "W1lOVUYtMjAyNi0xMDk2MTld" },
  "coverage": {
    "eligibleCohort": 312040,
    "returned": 1,
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

Unknown EPSS is explicit null, never 0; a real zero is `"status": "known",
"value": 0`. ADP-only and legacy scores surface via `cvssPrimary.status`
(`adp-only`, `legacy`) instead of a promoted number. Unknown dates are null and
excluded from dated views. Every response carries `provenance` and the
rate-limit headers from the [README](README.md#limits).
