# Priority lists

Site views covered: known-exploited, highest-forecast, new-critical,
rising-forecast, kev-due-soon, and ssvc-active. Separate signals, deterministic ordering,
no invented score.

## Endpoints

    GET /api/v1/priority/{listName}

`{listName}` is one of `known-exploited`, `highest-forecast`, `new-critical`,
`rising-forecast`, `kev-due-soon`, `ssvc-active`. Unknown names return `LIST_NOT_FOUND`.
Only `cursor` and `limit` paginate; the cohorts are fixed by the ranking
contract. `kev-due-soon` is live-only: retained checkpoints keep their
five-view contract, so replay never serves it.

## Ordering (also returned per response in `ordering`)

- `known-exploited`: KEV `dateAdded` descending, then ID ascending. EPSS is not
  a sort key here.
- `highest-forecast`: known EPSS raw probability descending, known date before
  unknown, publication descending, ID ascending. KEV is not a sort key here.
  Display values are `100 * epss` and `100 * percentile`; a 96th percentile is
  not a 96 percent probability.
- `new-critical`: publication in `[T - 30d, T)` with primary modern CVSS
  > = 9.0, publication descending, ID ascending. Unknown, legacy-only, and
  > ADP-only cases are ineligible, not low severity.
- `rising-forecast`: same-model `d` and `d - 7` observations, positive
  `deltaPp = 100 * (epss[d] - epss[d-7])` only; delta descending, current raw
  probability descending, ID ascending. Missing dates and model transitions are
  ineligible, never interpolated. Aligned deltas arrive in `deltaPp`.
- `kev-due-soon`: KEV members with a valid catalog remediation `dueDate`;
  due ascending (overdue first, no upper cutoff), ID ascending. Missing or
  malformed due dates are ineligible, never defaulted. Due dates are federal
  remediation deadlines, not exploit predictions.
- `ssvc-active`: records whose published CISA SSVC block says
  `Exploitation = active`. Technical impact `total` before `partial`,
  automatable `yes` before `no`, then the KEV catalog date descending (newest
  exploitation confirmation first), then raw EPSS probability descending, then
  ID ascending. All three keys are published CISA values; a record with no
  published SSVC block is ineligible, never assumed safe, and nothing is
  blended into a score.

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
      "kev": {
        "listed": true,
        "dateAdded": "2026-10-23",
        "dueDate": "2026-11-13",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "vulnerabilityName": null,
        "ransomwareUse": "unstated",
        "ransomwareKnown": null,
        "cwes": ["CWE-78"],
        "cweDetails": [
          {
            "id": "CWE-78",
            "status": "known",
            "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "abstraction": "Base",
            "mitigation": "Use a vetted library or framework that does not allow this weakness to occur.",
            "url": "https://cwe.mitre.org/data/definitions/78.html"
          }
        ]
      },
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
  "pagination": { "limit": 2, "hasMore": true, "nextCursor": "W1lOVUYtMjAyNi0xMDk2MTld" },
  "coverage": {
    "eligibleCohort": 1756,
    "returned": 1,
    "unscored": 40,
    "unknownEpss": 12,
    "unknownDate": 0
  },
  "cweCatalog": {
    "status": "ready",
    "version": "1000-956",
    "retrievedAt": "2026-11-14T00:00:00.000Z",
    "source": "MITRE CWE"
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

## CWE taxonomy labels

Every priority row carries `kev.cweDetails`: the local MITRE taxonomy's label
for each id in that row's `kev.cwes`, in the same order and deduped after
normalization. The whole page's ids resolve in **one** batched catalog lookup,
so a page never costs one lookup per row.

Contract:

- **Additive.** `kev.cwes` keeps its name and meaning as the ID-only list, and
  every other `CveItem` field is unchanged. Clients that ignore `cweDetails` see
  exactly the payload they saw before.
- **Never omitted.** Every id yields one entry, so `cweDetails` is `[]` only when
  `cwes` is `[]`. With no accepted catalog (never loaded, a failed refresh, or
  unreadable) each entry is `taxonomy-unavailable` with its canonical MITRE
  `url` — an absent taxonomy never removes an id from the array and never
  produces an invented name.
- `status` is `known` (id in the accepted catalog; carries the published `name`
  plus `abstraction`/`summary`/`mitigation` when the taxonomy published them),
  `unmapped` (well-formed id absent from the catalog, or an input with no valid
  CWE shape), or `taxonomy-unavailable`. The three states are never collapsed.
- Published `summary`/`mitigation` arrives with MITRE's `::…::` control markers
  stripped at projection time. Those markers are publishing markup, not content,
  so no payload contains `::`; stored catalog rows keep MITRE's verbatim text.
- Priority rows are the only list-shaped surface with labels. `GET /api/v1/cves`,
  search, and bulk rows stay ID-only; the per-record detail route carries the
  same labels as top-level
  [`cweDetails`](cves.md#cwe-taxonomy-labels-cwedetails).
- Taxonomy labels are context: they never change ordering, coverage, filters, or
  eligibility, and they are resolved locally (no upstream request).
- Every response also carries an additive envelope block, `cweCatalog`:
  `{ status, version, retrievedAt, source }` for the catalog that labelled this
  page. `version` is the accepted `<view id>-<entry count>` (e.g. `1000-956`)
  and is `null` when no catalog is accepted; clients label published mitigation
  guidance with this value instead of hard-coding a catalog version. It is
  provenance, not a verdict, and changes nothing about ordering or eligibility.
