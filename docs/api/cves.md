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
      },
      "cvssSecondary": {
        "status": "none",
        "coverageNote": "No secondary (ADP or non-selected CNA) metric is published. Any secondary would be context only and is not used for ranking or eligibility.",
        "metrics": []
      }
    }
  ],
  "pagination": { "limit": 2, "hasMore": true, "nextCursor": "W1lOVUYtMjAyNi0xMDk2MTld" },
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

## Secondary CVSS block

`cvssSecondary` rides on every `CveItem` (list, detail, and search) and never
replaces `cvssPrimary`. That is a payload contract, not a UI one: in the
console only the expanded Priority row renders the block, while Explore and
Watch rows stay static lists. Contract:

- `status` is `present` or `none`; `none` is explicit, never a missing key
- `coverageNote` states the guard in prose: these metrics are context only and
  are not used for ranking or eligibility
- `metrics` holds at most four entries: `origin`, `provider`, `version`,
  `baseScore`, `vector`, and `label` (always `secondary (context only)`)

The block excludes the one metric `cvssPrimary` selected, keeps both CNA and ADP
context, and orders ADP before CNA, then version preference 4.0 > 3.1 > 3.0 >
2.0, then base score descending on exact decimal text, then stored source order.
Malformed scores are skipped, never rendered. `baseScore` is exact published
text, not a number, so it is never re-rounded. Ranking, severity bands, filters,
and eligibility read `cvssPrimary` alone; `cvssSecondary` changes none of them.
An ADP-only record still reports `cvssPrimary.status: "adp-only"` with a null
score and shows the ADP metric as secondary context.

## EPSS history (detail only)

`GET /api/v1/cves/{cveId}` adds `epssHistory`: retained observations as
`{scoreDate, epss, modelVersion}`, oldest first, capped at the most recent
90, latest model per date. `null` means no observations were retained, never
zero. List and search items omit the key: history rides one bulk query per
rendered row set on the site, and per-record cost does not belong on
unbounded pages.
