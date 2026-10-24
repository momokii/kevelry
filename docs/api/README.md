# Public API v1 — human docs

Versioned read-only API for the CVE Change Radar site. The machine contract is
`openapi/v1.yaml`; these pages explain it. If this text and the spec disagree,
the spec wins and the docs-vs-spec test fails until they agree again.

Per-view pages:

- [cves.md](cves.md) — current published records and one-record lookup
- [search.md](search.md) — ID and description search behind the explore view
- [priority-lists.md](priority-lists.md) — the four named explainable orderings
- [radar.md](radar.md) — observed change feed with before/after evidence
- [replay.md](replay.md) — retained-checkpoint replay and checkpoint listing
- [overview.md](overview.md) — publication-volume aggregates behind the charts
- [status.md](status.md) — freshness, cohorts, notices, liveness

## Auth: none, by design

Public reads are anonymous. No tokens, no accounts, no per-user state. Imports,
migrations, and maintenance stay private CLI operations; there is deliberately
no write endpoint to authenticate against. Clients that need private use run
their own self-hosted copy and put their own access control in front of it.

## Conventions shared by every route

Base path: `/api/v1`. All responses are JSON. Every success response carries:

- `provenance.rankingPolicyVersion` — policy behind any ordering in the body
- `provenance.sources.{cve,kev,epss}` — revision or version, score date and
  model where applicable, last check, last acceptance, `stale` flag, last error
- `coverage` on list responses — eligible cohort plus unscored, unknown-EPSS,
  and unknown-date counts; unknowns are counted, never hidden

Unknown values are explicit. A missing EPSS row renders as
`"epss": {"status": "unknown", "value": null, ...}` and is never coerced to 0.
A real zero is `"status": "known", "value": 0`. Missing publication dates go to
an explicit unknown bucket and are excluded from dated views. See
[DATA_WORKFLOW.md](../DATA_WORKFLOW.md) for the full missing-data contract.

## Pagination

Cursor-based. `limit` defaults to 50 and caps at 200; oversized values are
rejected with `BAD_LIMIT`, not clamped. Responses carry
`pagination: {limit, hasMore, nextCursor}`; pass `nextCursor` back as `cursor`.
Cursors are opaque — never constructed by hand. Page example:

```bash
curl "https://radar.example.org/api/v1/cves?limit=50"
curl "https://radar.example.org/api/v1/cves?limit=50&cursor=W1lOVUYtMjAyNi0xMDk2MTld"
```

## Filters

`cves` and `search` share the explore-view filters, so the site and the API
read the same cohort:

| Param | Values | Notes |
| --- | --- | --- |
| `q` (search only) | 2–200 chars | ID or description text; local index only |
| `severity` | `critical`, `high`, `medium`, `low`, `unknown`, `legacy` | Primary-CNA band; CVSS versions not calibrated alike |
| `kev` | `listed`, `not-listed`, `any` (default) | Membership in accepted snapshot |
| `epss` | `scored`, `unscored`, `any` (default) | `unscored` means unknown, never zero |
| `publishedStart`, `publishedEnd` | RFC 3339 UTC | Half-open `[start, end)` interval |

Injection-shaped input is rejected with `BAD_QUERY` or `BAD_FILTER`; it never
reaches the query layer as code. See [SECURITY_STANDARDS](../.claude/SECURITY_STANDARDS.md).

## Freshness semantics

Reads never call upstream; they serve accepted local snapshots. A stale source
keeps its dated values with `stale: true` and the last error named. Thresholds:

- CVE / KEV stale when the last successful check is more than 3 hours old
- EPSS stale when the accepted score date is older than 2 UTC calendar days

Freshness fields live in `provenance.sources.*` on every response and in full
on the status route ([status.md](status.md)).

## Error catalog

All errors share `{code, message, details?, requestId?, provenance}`. `code` is
stable; `message` is sanitized; no stack traces, paths, or secrets.

| Code | HTTP | Meaning |
| --- | --- | --- |
| `BAD_REQUEST` | 400 | Generic rejected input |
| `BAD_CURSOR` | 400 | Malformed or foreign cursor |
| `BAD_LIMIT` | 400 | `limit` outside 1–200 |
| `BAD_QUERY` | 400 | `q` too short, too long, or unsafe |
| `BAD_FILTER` | 400 | Unknown enum value or bad combination |
| `BAD_DATE_RANGE` | 400 | Unparseable dates or `start >= end` |
| `CVE_NOT_FOUND` | 404 | No current `PUBLISHED` record for the ID |
| `LIST_NOT_FOUND` | 404 | Unknown priority list name |
| `CHECKPOINT_UNAVAILABLE` | 404 | No manifest for the date |
| `REPLAY_UNAVAILABLE` | 404 | Expired, missing, or model-changed; `details.reason` names it |
| `RATE_LIMITED` | 429 | Per-IP budget spent; `Retry-After` tells when to return |
| `INTERNAL` | 500 | Sanitized failure; report `requestId` |

## Limits

Defaults, enforced per client IP and visible on every response:

- 600 requests per minute per IP; bursts over the budget get `429 RATE_LIMITED`
- `limit` parameter capped at 200; `q` capped at 200 characters
- Request bodies are irrelevant (GET only) and URL length is bounded by the server
- Every `200` and `429` carries `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  and `X-RateLimit-Reset`; `429` adds `Retry-After`
- Expensive queries are time-bounded server-side and fail as `INTERNAL` rather
  than hanging; clients should retry with a narrower window

Tune the numbers per deployment; the header names and the `429` shape are stable.

## Versioning and deprecation policy

- The path major (`/api/v1`) is stable. Breaking changes ship as `/api/v2`,
  never as silent v1 changes. Additive fields are not breaking.
- A deprecated v1 route or field is announced in release notes and in the
  `notices` array of the status response, with a removal date at least 90 days
  out. Deprecated elements keep working until that date.
- Field availability is never the freshness signal: a field that is absent
  because its source is unknown renders as explicit `null` with a status label,
  not as a missing key. Unknown keys are never added ad hoc; every documented
  field exists in `openapi/v1.yaml`.
- Consumers should pin the spec revision they built against and re-validate on
  upgrade. The docs-vs-spec test (`tests/api-contract.test.ts`) enforces that
  every documented endpoint exists in the spec before any route is implemented.
