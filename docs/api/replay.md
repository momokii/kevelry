# Snapshot replay

Site view covered: replaying a retained daily checkpoint with its recorded
policy version to see what the site showed then.

## Endpoints

    GET /api/v1/replay/checkpoints
    GET /api/v1/replay

Checkpoints lists retained manifests newest first with coverage bounds
(`retainedFrom`, `retainedTo`). Replay re-evaluates one priority `view` from
the checkpoint's pinned snapshots and recorded policy version; `date`
(`YYYY-MM-DD`) and `view` are required.

## Unavailable means unavailable

History before launch was never observed and is not fabricated. Expired or
missing checkpoints, and model-changed comparisons, return `404
REPLAY_UNAVAILABLE` with a named `details.reason` (`expired`, `missing-day`,
`model-changed`) — current data is never substituted.

## Example

```bash
curl "https://radar.example.org/api/v1/replay/checkpoints?limit=5"
curl "https://radar.example.org/api/v1/replay?date=2026-10-17&view=highest-forecast&limit=2"
```

```json
{
  "checkpointDate": "2026-10-17",
  "view": "highest-forecast",
  "rankingPolicyVersion": "ranking-v1",
  "data": [
    {
      "cveId": "CVE-2026-109618",
      "title": "CVE-2026-109618",
      "state": "PUBLISHED",
      "publishedAt": "2026-10-10T14:02:00Z",
      "officialUrl": "https://www.cve.org/CVERecord?id=CVE-2026-109618",
      "excerpt": "A denial of service flaw was found in the packet parser ...",
      "excerptTruncated": true,
      "excerptLanguage": "en",
      "excerptStatus": "present",
      "kev": { "listed": false, "dateAdded": null },
      "epss": {
        "status": "known",
        "value": 0.1,
        "percentile": 0.95,
        "scoreDate": "2026-10-17",
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
    "eligibleCohort": 310900,
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

An expired date answers:

```json
{
  "code": "REPLAY_UNAVAILABLE",
  "message": "Checkpoint 2026-08-01 is expired. Retained window starts 2026-09-24.",
  "details": { "reason": "expired", "retainedFrom": "2026-09-24", "retainedTo": "2026-10-23" }
}
```

Every response carries `provenance` and the rate-limit headers from the
[README](README.md#limits).
