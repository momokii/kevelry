# Search

Site view covered: explore and search results (query, filters, excerpts,
official links, missing and language states).

## Endpoints

    GET /api/v1/search

Local FTS-backed search over accepted snapshots only. No nickname index is
promised and no upstream fetch occurs. Either `q` (2–200 chars) or `vendor`
(2–100 chars) must shape the query; results mirror the explore view row
for row.

## Parameters

`q` plus `cursor`, `limit`, and the shared filters (`severity`, `kev`, `epss`, `exploit`,
`publishedStart`, `publishedEnd`, `vendor`); see [README](README.md#filters).
`vendor` is a substring over KEV catalog vendor/product labels: only
KEV-listed records carry these labels, so it implies KEV membership. The
response echoes both `q` (empty for vendor-only searches) and `vendor`
(null when unfiltered).

## Bounded export (`format`)

`format=csv` and `format=json` serialize **the page this request already
returned**. Validation, filters, ordering, `limit` and `cursor` are the ones
described above: the export is the current page, never a dump, and there is no
second scan or fan-out. An absent `format` keeps the JSON envelope exactly as
before; any other value is `400 BAD_FILTER`. `/api/v1/search` still requires `q`
or `vendor`, so there is always a query for the file to describe.

Both formats are sent as attachments:

    Content-Disposition: attachment; filename="kevelry-search-<UTC date>-<n>rows.csv"
    Content-Disposition: attachment; filename="kevelry-search-<UTC date>-<n>rows.json"

`<n>` is the number of data rows in the file, so a saved file says how big the
page it came from was.

### CSV columns

UTF-8, CRLF record separator, header row, then one row per record, in this
stable order (additive changes only, never reordering):

    cveId,title,state,publishedAt,updatedAt,severityBand,primaryCvssVersion,primaryCvssScore,kevListed,kevDateAdded,epssValue,epssPercentile,exploitTagged,officialUrl

- `severityBand` is the same primary-CNA band the site renders (`critical`,
  `high`, `medium`, `low`, `none`, `legacy`, `unknown`); it is not a second,
  export-only classification.
- `primaryCvssVersion`/`primaryCvssScore` are the selected primary metric;
  `epssValue`/`epssPercentile` are the accepted snapshot's decimals as stored
  (never rounded into a different number).
- `kevListed` and `exploitTagged` are `true`/`false`. `exploitTagged` means a
  reference carries the publisher's `exploit` tag — a classification, not a
  verified working exploit.
- Quoting is RFC 4180: a field containing a comma, a double quote, CR or LF is
  wrapped in double quotes and embedded quotes are doubled.
- Null or absent values are **empty cells** — never `null`, `-` or `0` — so an
  unknown KEV date or EPSS value is visibly absent instead of looking measured.
- The file is a header row plus data rows, and nothing else. It carries **no
  `#` comment lines**: spreadsheet and SQL importers would read those as data.
  Provenance (`provenance`) and coverage (`coverage`) stay in the JSON envelope
  and beside the export control in the UI.

### JSON export

`format=json` is the same envelope as the plain response (`q`, `vendor`, `data`,
`pagination`, `coverage`, `provenance`) with the attachment header added. ETag
and `Cache-Control` behave exactly like the JSON route, so a conditional repeat
answers `304`.

## Example

```bash
curl "https://radar.example.org/api/v1/search?q=openssl%20denial%20of%20service&limit=2"
curl "https://radar.example.org/api/v1/search?vendor=microsoft&limit=2"
curl -o kevelry-search.csv "https://radar.example.org/api/v1/search?q=openssl&limit=5&format=csv"
```

```json
{
  "q": "openssl denial of service",
  "vendor": null,
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
  "pagination": { "limit": 2, "hasMore": false, "nextCursor": null },
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
