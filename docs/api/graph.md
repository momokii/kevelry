# Relation graph

Site view covered: the relation graph over the KEV-listed cohort (shared
catalog CWEs, normalized vendor labels, reference hostnames).

## Endpoints

    GET /api/v1/graph?focus=CVE-2026-109618&limit=120

`focus` is optional, and **no center is chosen for the reader**. Without it the
response is landing mode: `hubs` ranks the most-connected records (with their
strongest shared attributes) and `nodes`/`edges`/`groups` are empty. With
`focus` the response is that record's neighborhood, expressed twice:

- `groups`: bipartite buckets — one per shared attribute value, each listing
  the neighbor CVE ids that carry it. This is the readable view ("shared
  CWE-94 · 14 records") and the one the site renders.
- `nodes` + `edges`: the same neighborhood as a node-link set, for clients
  that want to draw it.

`limit` (1–300, default 120) caps the neighborhood. Unknown or non-KEV focus
returns `CVE_NOT_FOUND`.

## Edges

Edges join records that share an honest, labeled attribute — never inferred
relations:

- `cwe`: a shared catalog CWE identifier (deduped, capped per record).
- `vendor`: the same normalized vendor label (trimmed, lowercased).
- `domain`: a shared reference hostname (`http(s)` schemes only). Hosts
  referenced by more than 15% of the cohort (floor 20 records) are pruned as
  advisory aggregators — `securityfocus.com`, `exploit-db.com` and friends
  describe the corpus, not a relationship between two records.

Each edge also carries `evidence` naming the concrete shared attributes:
`cwes` (identifiers, escapable to MITRE), `vendor` (label or null), and
`domains` (hosts, sorted). The API names every kind in `kinds`, sorted. Node
and edge caps ride in the response (`coverage` + `truncated`); nothing is
sampled silently.

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
  "edges": [
    {
      "from": "CVE-2026-109618",
      "to": "CVE-2026-110447",
      "kinds": ["cwe", "vendor"],
      "evidence": {
        "cwes": ["CWE-94"],
        "vendor": "microsoft",
        "domains": ["docs.microsoft.com"]
      }
    }
  ],
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
