# v2 scope: researched 2026-10-30, decided same day

Question: what makes a MAJOR version worth announcing (dark theme, watch,
CVE story strips, relationship graph, linked mitigation/news context, more
free data) without breaking the contracts (read-only, anonymous, single
image, free feeds, no composite scores, unknown stays unknown)?

## Verified live (this session)

| Claim                          | Check                                                      | Result                                                                                                                                          |
| ------------------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| GHSA records joinable to CVE   | `api.github.com/advisories?ecosystem=pip`                  | 200; records carry `cwes[]` (id+name), `identifiers[]` (GHSA+CVE crosswalk), `cvss_severities`, `references[]`, `epss`, published/updated dates |
| OSV answers "am I affected"    | POST `api.osv.dev/v1/query` jinja2@2.11.3                  | 200; `affected[].ranges[]` with `introduced`/`fixed` events + pinned versions                                                                   |
| NVD CPE matching works keyless | `cves/2.0?cpeName=...&resultsPerPage=1`                    | 200, valid envelope (0 hits for the probe string; mechanics proven)                                                                             |
| CWE taxonomy downloadable      | `cwe.mitre.org/data/xml/cwec_latest.xml.zip` (range probe) | 206; pack exists (Mitigations-node structure per CWE XML schema, verify on import)                                                              |
| BleepingComputer RSS exists    | `/feed/`                                                   | 200 (reuse terms unconfirmed; link-out only at most)                                                                                            |
| CISA alerts RSS reachable      | `/uscert/ncas/alerts.xml`, advisories page                 | 403 bot-wall from here; NOT verified, confirm in a browser                                                                                      |
| Local graph materials exist    | repo inventory                                             | shared CWE (`kev_cwes`, this release), shared vendor/product, reference domains in `raw_json`, FTS5-porter descriptions, EPSS bands             |
| Anonymous watch feasible       | repo inventory                                             | localStorage precedent (`ui-rail-collapsed`, timezone); no server state needed                                                                  |
| Theming is tokenized           | repo inventory                                             | `app/ui.css` runs on `--ui-*`/`--ledger-*` vars; charts read `var()`                                                                            |

## Verdicts (honest)

- **Dark theme: YES, v2-core.** Tokenized already; add `data-theme="dark"` + persisted toggle. Must audit every surface incl. `globals.css` legacy styles and SVG fills. High perceived value, zero contract risk.
- **Watch (localStorage-only): YES, v2-core.** Star toggles on rows + a `/watch` view hydrating stored IDs through the read-only API. No accounts, no server state; anonymous design intact. Quota-guarded (e.g. 200 IDs) with an honest cap message.
- **CVE story strip: YES, v2-core.** Expanded rows gain a horizontal timeline from retained dates only: published → KEV listed → remediation due → EPSS trend window. No new data, pure explanation. This is the "useful and full" feel without a single new feed.
- **Relationship graph ("second brain"): YES, v2-core, bounded.** Corpus graph over the KEV-listed cohort (~1.7k nodes, labeled bounded): edges for shared CWE, shared vendor, shared reference domain; inspector + click-through to explore. No invented relations, no text-similarity guessing in v1 of the graph (FTS term-overlap stays a documented future, not a silent edge).
- **Mitigation context: PARTIAL.** `requiredAction` (already shown) + CWE names (already stored) ship now. Full CWE Mitigations text needs the taxonomy import pipeline — v2-batch-2, not this turn.
- **Security news: NO.** CISA RSS unverifiable from here; third-party news reuse terms unclear; a stale/broken news box would rot the product's trust. Revisit only with a verified free feed + link-out-only design.
- **Exploit how-to: REFUSED.** Safety stance and product contract: evidence and remediation direction only, never weaponization enablement. Not negotiable, not a roadmap item.
- **NVD CPE / OSV affected / GHSA cross-refs: v2-batch-2.** Each needs an import pipeline with the same fallback discipline as the current three feeds. Researched and queued, not started here.
- **CVSS vector decoder: dropped.** Vectors already display; a calculator adds UI weight without answering a user question the product poses.

## v2-core build order (this turn)

1. Dark theme (tokens + toggle + audit). 2. Watch (hook + toggles + `/watch`
   view + cap). 3. Story strip (timeline in expanded rows). 4. Relation graph
   (bounded KEV-cohort view + inspector). Each commits separately with tests;
   docs (README screenshots, DESIGN tokens, methodology where ordering appears)
   update with the change that causes them.
