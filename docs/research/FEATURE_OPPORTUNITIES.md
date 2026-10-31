# Feature opportunities: researched 2026-10-30

Question: what can this app grow into without breaking its contracts
(read-only, anonymous, single image, free feeds only, no composite scores,
unknown stays unknown)? Method: repo inventory plus live checks against
first-party endpoints. Every external claim below was fetched on 2026-10-30
unless marked otherwise.

## Verified live (this session)

| Endpoint                                            | Result            | What it proves                                                                                                           |
| --------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `services.nvd.nist.gov/rest/json/cves/2.0?cveId=`   | 200, record JSON  | NVD API v2 is openly queryable, no key                                                                                   |
| `api.osv.dev/v1/query` (POST, Debian/openssl)       | 200, vuln list    | OSV ecosystem queries need no auth                                                                                       |
| `api.github.com/advisories?ecosystem=pip`           | 200               | Advisory REST list is public unauthenticated                                                                             |
| `cisa.gov/.../known_exploited_vulnerabilities.json` | fields enumerated | KEV rows carry `dueDate`, `requiredAction`, `knownRansomwareCampaignUse`, `cwes`, `vulnerabilityName` — none stored here |
| `api.github.com/repos/CERTCC/SSVC`                  | public repo       | SSVC decision-tree methodology is implementable locally, no feed                                                         |
| `cwe.mitre.org/data/downloads.html`                 | 200               | CWE taxonomy freely downloadable                                                                                         |
| `cve.org/api/`                                      | 200               | CVE Services docs endpoint live                                                                                          |

Repo inventory (no new feed needed): `getEpssHistory(db, cveId)` exists in
`src/lib/epss-import.ts` but has **zero production callers** — per-CVE EPSS
trend data is retained and unexposed. `kev_entries` stores `vendor_project`
and `product`, never searched or displayed. `epss_daily` accumulates dated
observations (rising-forecast already requires d-7).

Bot-walled (not verified, do not cite as checked): nvd.nist.gov developer
rate-limit docs, FIRST EPSS model page (moved), CISA SSVC landing page.
NVD/OSV/GitHub rate limits for keyless use must be confirmed from their docs
during implementation, not assumed from a 200.

## Tier 1 — data already retained, no new feed

1. **Per-CVE EPSS trend sparkline.** Wire `getEpssHistory` into the detail
   payload + a small SVG trend on expanded rows and the API. Same snapshot
   honesty (dated points, model-labeled); rising-forecast already proves the
   retention. Effort S, impact high.
2. **KEV enrichment.** Store and show `dueDate` (federal remediation
   deadline — the most actionable date we ignore), `knownRansomwareCampaignUse`
   (boolean flag, high signal density), `requiredAction`, `vulnerabilityName`,
   and `cwes`. A "due within 30 days" view fits the no-composite rule (it is a
   calendar filter, not a score). Effort S–M.
3. **Vendor/product search.** The columns exist and are indexed-cheap; add an
   explicit vendor/product query path beside description search. Effort S.

## Tier 2 — new free feeds, contract-aligned

4. **NVD API v2 as a secondary enricher** (CWE IDs, NVD-supplied CVSS,
   reference tags, CPE match strings). Local-first stays: NVD fills gaps the
   CVE record leaves, labeled by origin, never overwriting CNA primacy.
   Watch the keyless rate budget; cache aggressively. Effort M.
5. **OSV ecosystem queries** ("am I affected" for a package@version).
   Version-range answers are the closest honest thing to asset matching
   without holding user inventory. Effort M.
6. **GitHub Advisory aliases + reviewed CWEs** as cross-references on detail
   views (GHSA IDs, reviewed severity bands). Effort S–M.
7. **SSVC calculator view.** No feed: implement the CERTCC decision tree
   (exploitation × automatable × technical impact × mission prevalence) as an
   interactive explainer producing a priority outcome with its inputs shown.
   The most on-brand feature here: explainable triage with no hidden math.
   Effort M.
8. **CWE weakness lens.** Map records to CWE IDs (from NVD/KEV `cwes`), add a
   weakness breakdown beside severity bands. Effort M (needs #4 or KEV `cwes`).
9. **Radar as RSS/Atom.** Anonymous alerting that fits the no-accounts design:
   the change feed serialized for feed readers. Effort S.
10. **CSV/JSON export of bounded lists.** Analysts live in spreadsheets; a
    download button on priority/explore (bounded, labeled) removes copy-paste
    toil. Effort S.

## Tier 3 — conflicts or out of scope (honest no)

- **Accounts, watchlists-as-a-service, email/push alerts.** Conflict with
  anonymous-by-design. The aligned alternative is localStorage watchlists
  (private to the browser, no server state) + RSS (#9). Do those instead.
- **Paid telemetry** (exploit-intel vendors, commercial EPSS-like scores).
  Violates the free-feeds-only feasibility basis; revisit only with explicit
  owner funding and a recheck of FIRST terms.
- **PoC/exploit content.** Links to advisories only; never fetch, render, or
  execute exploit code. Existing stance, unchanged.
- **Generative AI summaries.** Conflicts with the no-estimation contract
  (a fluent paragraph invents connective tissue). Extractive excerpts only;
  revisit only with a citations-or-nothing design.

## Recommended build order (impact ÷ risk)

1. EPSS trend (#1) → 2. KEV due-date view + flags (#2) → 3. vendor/product
   search (#3) → 4. RSS radar (#9) → 5. export (#10) → 6. SSVC calculator (#7)
   → 7. NVD enrichment (#4) → 8. OSV affected-queries (#5) → 9. GHSA
   cross-refs (#6) → 10. CWE lens (#8).

First three ship on data already in the volume: no migration risk beyond
additive columns/tables, no new upstream failure modes, no terms exposure.
#4+ each add one upstream dependency and must repeat the fallback discipline
(last-known-good, per-source stale flags) the current three feeds follow.

## Terms gates (owner calendar, not code)

- NVD API keyless rate limits + redistributionTerms: confirm at implementation.
- OSV/GitHub Advisory: confirm redistribution + attribution wording.
- KEV `dueDate`/`requiredAction` display: covered by existing CC0 catalog
  basis, but re-confirm alongside the pre-launch terms recheck.
- Never monetize any of this without repeating the FEASIBILITY.md recheck.
