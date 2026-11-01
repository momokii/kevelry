# Relation graph

Site view covered: the relation graph over the KEV-listed cohort (shared
catalog CWEs, normalized vendor labels, reference hostnames).

## Endpoints

    GET /api/v1/graph?focus=CVE-2026-109618&limit=120

`focus` is optional: without it the cohort is the top-EPSS KEV-listed
published records up to `limit` (1–300, default 120). With it the response
is the ego neighborhood (the focus plus every directly linked record).
Unknown or non-KEV focus returns `CVE_NOT_FOUND`.

## Edges

Edges join records that share an honest, labeled attribute — never inferred
relations:

- `cwe`: a shared catalog CWE identifier (deduped, capped per record).
- `vendor`: the same normalized vendor label (trimmed, lowercased).
- `domain`: a shared reference hostname (`http(s)` schemes only).

Line style names the kind on the site (solid, dashed, dotted); the API
names every kind in `kinds`, sorted. Node and edge caps ride in the
response (`coverage` + `truncated`); nothing is sampled silently.

## Example

```bash
curl "https://radar.example.org/api/v1/graph?limit=2"
```

```json
{
  "focus": null,
  "nodes": [
    {
      "id": "CVE-2026-109618",
      "title": "CVE-2026-109618",
      "band": "critical",
      "epss": "0.1162",
      "kevDueDate": "2026-11-13",
      "degree": 1
    }
  ],
  "edges": [{ "from": "CVE-2026-109618", "to": "CVE-2026-110447", "kinds": ["cwe"] }],
  "coverage": { "eligibleCohort": 1762, "returned": 1, "edgeCount": 1 },
  "truncated": true,
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

Every response carries `provenance` and the rate-limit headers from the
[README](README.md#limits).
