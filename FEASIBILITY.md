# CVE dashboard feasibility

Audited: 2026-10-24. **Documentation complete; website build not approved or started.**
Product workflow and ranking remain proposals pending owner approval.

## Read This First

| Document | What it establishes |
|---|---|
| [Source audit](docs/research/SOURCES.md) | Primary-source access/reuse evidence, confidence, endpoints, fields, live validations and exclusions |
| [Competitor audit](docs/research/COMPETITORS.md) | Tested URLs, observed versus claimed features, blocked/browser limits, build-versus-use verdict |
| [Data workflow and ranking](docs/DATA_WORKFLOW.md) | Proposed exact normalization, ingestion/recovery, freshness, ranking keys, formulas, examples and acceptance gates |

Evidence is dated and claims are scoped. **Verified** means a cited source or observed
read supports that claim; **proposed** means our product policy; **unverified** means
not tested or evidence unavailable. No confidence percentage is invented.

## Feature Coverage

| Requested feature | Selected data / confidence | Fulfilled by sources? |
|---|---|---|
| Overall published-CVE charts | CVE List V5 publication timestamps/state; high source fit | Yes, with UTC buckets, unknown-date coverage and correction/rejection handling |
| Search CVE ID and description | CVE ID and upstream descriptions; high source fit | Yes; local search implementation and performance not yet tested |
| Short description before official link | CNA descriptions plus constructed CVE.org ID link; high source fit | Yes where text exists; explicit missing-text/language behavior |
| Severity/date/KEV/EPSS filters | Source fields and source-dated joins; unknown full-corpus coverage | Conditional: severity uses primary CNA metrics only; ADP-only/legacy/unknown cases are separate; date and join gaps stay visible |
| Transparent top/priority lists | KEV evidence, EPSS forecast and supplied CVSS; high signal fit | Yes as separate signals and deterministic policy, not a calibrated custom risk score |
| New critical CVEs | Selected modern primary CNA CVSS and publication date | Conditional: primary CNA metric and timestamp required; ADP-only cases excluded by proposed policy; coverage unmeasured |
| Rising forecast | Two exact daily EPSS observations under one model | Conditional: history required; exclude missing days/model changes |
| Social popularity / most talked about | No validated source selected | No; EPSS/KEV do not measure this |
| Nickname search, e.g. PHP2Shell | Only text actually indexed from records | Not guaranteed; curated aliases would be separate optional editorial work |
| Complete reservation counts / Osprey forecast parity | No full unpublished reservation list or validated projection model | Not covered; basic publication overview is covered, not every Osprey control/model |

**Answer to "are all features fulfilled?": not literally all.** The core public
overview/search/excerpt/exploitation-priority site has a viable source basis. True
popularity, universal aliases/severity and exact Osprey feature parity are not promised.
This distinction must be accepted before claiming the MVP scope is fully covered.

## Confidence and Build Readiness

High confidence: current anonymous access, CVE/KEV reuse evidence, EPSS free bulk
access, available fields and o2CVE's substantial feature overlap. Medium confidence:
FIRST service-term interpretation for a specific public preventative use; clarify
before commercialization. Unverified: full CVE import, database/search performance,
sustained sync recovery, complete join/metric coverage, production costs and uptime.

The full daily EPSS file was downloaded and structurally validated: 394,803 unique
rows, zero invalid rows in the stated checks; KEV had 1,756 entries with matching
declared/actual/unique counts. Exact timestamps, hash and scope are in the source
audit. These tests do not validate EPSS predictions or benchmark the future website.

**Go:** approve a bounded scope and plan a prototype/ingestion benchmark.
**Not yet a production go:** owner policy/stack/hosting approval, benchmark targets
and results, source notices, recovery tests and public-page acceptance remain open.

The sections below retain the first reconnaissance's dated context. When detail is
needed, the linked source audit and exact workflow contract govern; they supersede
the earlier illustrative Heat formula and unspecified ranking tie-breakers.

## Verdict

A small public website with CVE-volume charts, prioritized lists, search, short
descriptions, and links to official records is feasible without paid data sources.
Free data is not a promise of free hosting, unlimited API use, future availability,
complete coverage, or an uptime SLA. Preserve attribution and source terms.

The concept already exists. The opportunity is a simpler, transparent, independently
maintainable implementation, not a unique vulnerability-intelligence product.

## Existing alternative

[o2CVE](https://o2cve.com/) currently offers a priority-ranked list, search, and
[statistics](https://o2cve.com/stats). Its [method](https://o2cve.com/method) publishes
the score factors. Its [search](https://o2cve.com/cve?q=php) supports product, vendor,
publication-date, score and exploitation filters, with description excerpts.
Its [API](https://o2cve.com/api) documents free read access, 60 requests/hour/IP without
a key, 1,000/day with a free key, and daily compressed JSONL/CSV exports.
This verifies overlapping advertised features, not completeness or an uptime SLA.
CVEDetails returned HTTP 403 to this research client; its current feature set was not
independently reverified here. Do not rely on earlier exhaustive competitor claims.

## Source decision

| Source | Cost and reuse | Access | MVP decision |
|---|---|---|---|
| CVE List V5 | No-charge reuse, derivatives, display and distribution under CVE terms; reproduce MITRE copyright designation and license | Official repository; daily baseline, hourly delta assets | Required: records, descriptions, publication dates, references, available CNA/ADP metrics |
| CISA KEV | CC0 1.0; no implied endorsement or right to CISA/DHS branding | Static JSON/CSV or official GitHub mirror; no paid account | Required: evidence of known exploitation, date added |
| FIRST EPSS | Scores free, no registration; FAQ requests attribution in products; services terms permit distribution for preventative cybersecurity uses with notices retained | Full daily compressed CSV; API for individual/small-batch lookups | Required: probability and percentile, score date, model version |
| NVD | Public developer access; quotas and attribution/disclaimer requirements need checking before integration | API and bulk feeds | Optional later: richer CPE/CVSS coverage; not necessary for core MVP |
| Shodan CVEDB | Free only for non-commercial use; enterprise license needed to make money | Daily API, no key | Exclude from core so monetization does not create a paid-data dependency |
| Social feeds, vendor risk scores, community PoC indexes | Terms, coverage and availability vary; public GitHub content is not automatically licensed for redistribution | Mixed | Exclude from core; no paid or unverified popularity feed |

Primary evidence:
- [CVE List V5 README](https://github.com/CVEProject/cvelistV5#readme): official list,
  updates about every seven minutes, baseline and delta distribution. Hourly assets
  contain cumulative changes since the baseline, not just the previous hour.
- [CVE terms](https://www.cve.org/Legal/TermsOfUse), also readable in the
  [official website source](https://github.com/CVEProject/cve-website/blob/dev/src/views/Legal/TermsOfUse.vue).
- [KEV license](https://github.com/cisagov/kev-data/blob/develop/LICENSE) and
  [official mirror](https://github.com/cisagov/kev-data).
- [EPSS data access](https://www.first.org/epss/data),
  [FAQ](https://www.first.org/epss/faq), and
  [FIRST services terms](https://www.first.org/about/policies/terms).
- [Shodan CVEDB terms on its landing page](https://cvedb.shodan.io/).

This is a practical source review, not a legal opinion or a guarantee that terms
will never change. Recheck terms before launch and before adding monetization.
Link to vendor advisories rather than copying their prose, logos or exploit code.

## Live access verification

Public reads were performed without API keys:
- CVE List V5 record `CVE-2026-109618` returned valid JSON, state `PUBLISHED`,
  publication date `2026-10-21`, and an upstream description of PHP OOM cleanup RCE.
- KEV mirror returned catalog `2026.10.23`, with declared and actual counts both 1,756.
- EPSS lookup for that CVE returned probability `0.1162`, percentile `0.96047`,
  dated `2026-10-23`. The daily CSV resolved to HTTP 200, 2,767,303 compressed bytes.
- At research time o2CVE displayed 5.3% EPSS for that CVE, versus FIRST's dated 11.62%.
  This illustrates snapshot disagreement; it does not establish a systematic defect.

Successful lookups are not a full ingestion benchmark. Whole-corpus import time,
disk consumption, search latency, and operating cost remain unmeasured.

## Ranking proposal

The earlier weighted Heat formula was an illustrative heuristic, not a validated
scoring model. It is superseded by the [exact proposed ranking contract](docs/DATA_WORKFLOW.md#ranking-proposal-v1),
including CVSS selection, missing data, stable ties, date boundaries and worked examples.
Do not present that earlier formula as a calibrated risk or popularity score.
CVSS is severity, EPSS is predicted observed exploitation, and KEV is known
exploitation evidence. They are not interchangeable.

Prefer separate, explainable lists in the first version:
1. Known exploited: KEV members first; optionally show newest KEV additions.
2. Highest predicted exploitation: descending EPSS probability with its date.
3. New critical: published in a selectable recent window, with CVSS >= 9.0;
   show the score source and version. Missing CVSS is unscored, not low severity.
4. Rising forecast: largest seven-day EPSS probability increase, only when both
   observations exist and use the same model version. It is not social popularity.

If one default priority ordering is needed, use an explicit rule: KEV tier first,
then EPSS probability descending within tiers, then a deterministic tie-breaker.
Show unknown EPSS separately/after scored records within its tier. Keep severity
available as an independent sort/filter, with the score's version/provider visible.
Document the ordering as an editorial policy, not an official 0-100 risk score.

A new headline issue can have no EPSS yet and not be in KEV. Therefore these feeds
cannot guarantee that PHP2Shell or any other heavily discussed issue tops the list.
An optional manually curated spotlight with an official advisory link can cover that
gap; it must be labeled editorial and stay separate from the automated ranking.

## Proposed minimal pipeline

```text
CVE List V5 baseline + hourly cumulative delta ----+
CISA KEV JSON -----------------------------------+--> validate / join by CVE ID
FIRST EPSS daily CSV -----------------------------+             |
                                                               v
                                          local store + search index
                                                               |
                                                               v
                                          aggregates + ranked lists + website
```

No visitor request should require an upstream API call. The ingestion worker owns
downloads; public search and charts read a local snapshot. No paid model or LLM
is necessary: excerpts come from the upstream description, not generated summaries.

Proposed schedule: CVE records hourly, KEV hourly with conditional requests where
supported, EPSS daily after its normal publication time. Retain the source's actual
date separately from retrieval time. Archive a bounded EPSS history for rising lists.
Choose the scheduler and hosting only after checking their current quotas and terms.

Proposed entities, not an approved database schema:
- `cve_records`: ID, state, title if present, original description, affected labels,
  publication/update times, upstream references and source revision.
- `cvss_metrics`: CVE ID, provider, score, vector and version. Preserve disagreements;
  use a documented selection policy instead of silently choosing the largest score.
- `epss_daily`: CVE ID, date, probability, percentile and model version.
- `kev_entries`: CVE ID, date added and relevant catalog fields.
- `sync_runs`: source, revision/date, retrieval time, validation status and error state.

Reliability requirements: idempotent imports, validated upstream payloads, atomic
snapshot publication, last-known-good data during upstream outages, visible stale
warnings, and periodic reconciliation against a full baseline. Rejected records must
leave normal rankings/counts; count publications by publication date, not ID year.
Reserved dates in published records do not measure all unpublished reservations.
Treat absent fields as unknown. Search results should show ID, description excerpt,
score provenance and a direct `https://www.cve.org/CVERecord?id=<CVE-ID>` link.

## Scope and remaining gates

Initial scope: volume charts, the explainable top lists, search/filter, excerpts,
official links, source dates and an attribution/methodology page. No accounts,
alerts, asset scanner, social scraping, exploit execution, or bespoke detail pages.

Recommendation: proceed as a modest side project if ownership and a simpler UX are
the goal; use o2CVE first if the goal is only to consume this information.
Before implementation, approve the ranking policy and stack, benchmark an initial
bulk import, and choose hosting. Source access can cost zero; infrastructure cost
depends on traffic, database size, compute, bandwidth and the host's current terms.

## Agent routing

Project-local `opencode.json` and `.omo/omo.jsonc` pin configured delegation agents
and categories to `openai/gpt-6-luna`, with cross-model runtime fallback disabled.
The deeper audit used a planner, two researchers, a documentation writer and a final
read-only reviewer. Actual child-session assistant metadata was checked and showed
`openai/gpt-6-luna` for all five. This runtime observation supersedes the earlier
unverified restart blocker.
