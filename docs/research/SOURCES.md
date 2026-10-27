# Source Access and Reuse Audit

Checked: 2026-10-24. Scope: a public preventative-cybersecurity dashboard, not an
unrestricted commercial intelligence feed. These are dated findings, not legal advice.

## Evidence Levels

- **High:** direct first-party documentation and/or a successful observed data read.
- **Medium:** plausible use supported by terms, with interpretation or unmeasured operations.
- **Unverified:** not checked successfully; no promise should depend on it.

Confidence applies to the named claim, not the entire service. Successful reads do not
establish complete coverage, continuous availability, unlimited use, or future terms.

## Source Decisions

| Source                   | Access                                                   | Public-use basis                                                                                                             | Confidence / decision                                                                                               |
| ------------------------ | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| CVE List V5              | Public Git repository, raw files and release downloads   | CVE terms permit reproduction, derivatives, display and distribution with MITRE copyright designation and license reproduced | High for current access/reuse; core                                                                                 |
| CISA KEV                 | Public JSON/CSV and official GitHub mirror               | Catalog data is CC0 1.0; third-party links and government marks are not covered                                              | High for current access/reuse; core                                                                                 |
| FIRST EPSS               | Free daily full CSV and small-batch API, no registration | FAQ requests product attribution; services terms permit specified cybersecurity uses with notices retained                   | High for access; medium for legal interpretation of a particular public deployment; core subject to purpose/notices |
| NVD                      | Optional API/feeds                                       | Current detailed quota and reuse review not completed here                                                                   | Unverified optional enrichment; not a build prerequisite                                                            |
| Shodan CVEDB             | Free API without account for non-commercial use          | Landing page requires enterprise licensing to make money                                                                     | Verified restriction; exclude from core                                                                             |
| Social/PoC/vendor scores | Mixed and source-specific                                | No uniform free redistribution basis established                                                                             | Exclude from core; no popularity promise                                                                            |

Free access and permission to display are separate questions. Before ads, paid access,
resale or other commercialization, recheck every source and clarify FIRST's terms.
Avoid implying upstream endorsement. Hosting and database costs are separate from data fees.

## CVE List V5 Contract

First-party evidence: [official README](https://github.com/CVEProject/cvelistV5#readme),
[terms](https://www.cve.org/Legal/TermsOfUse),
[readable official website terms source](https://github.com/CVEProject/cve-website/blob/dev/src/views/Legal/TermsOfUse.vue),
[record schema](https://github.com/CVEProject/cve-schema).

The README calls this the official CVE List, updated "about every 7 minutes" from
the official CVE Services API. This is a stated cadence, not a maximum-latency SLA.
GitHub's API quotas apply if that API is used; bulk Git/release access is a different
path and should not be replaced with hundreds of thousands of per-file API requests.

The CVE usage license authorizes "reproduce, prepare derivative works of, publicly
display, publicly perform, sublicense, and distribute" and requires that copies
"reproduce MITRE's copyright designation and this license." It is no-charge reuse,
not CC0. Public display and derived ordering are supported subject to these conditions.
Retain the full applicable license/notice in distributed data and on the site's
attribution page; a bare source link is not a substitute for reproducing required text.

| Field / path                                                   | Use / qualification                                                          |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `dataVersion`                                                  | Select the record-format schema; mixed versions exist                        |
| `cveMetadata.cveId`, `.state`                                  | Identity and public record state                                             |
| `cveMetadata.datePublished`, `.dateUpdated`                    | Publication/update chronology, not ingestion time                            |
| `containers.cna.title`, `.descriptions[].lang/value`           | Title if supplied; original description by language                          |
| `containers.cna.metrics[]`                                     | Optional CNA metrics, including versioned CVSS                               |
| `containers.cna.affected[]`                                    | Provider-supplied vendor/product labels; not normalized exhaustive inventory |
| `containers.cna.references[]`, `containers.adp[].references[]` | References with container/provider provenance                                |
| `containers.adp[].metrics[]`                                   | Optional enrichment; preserve provider and distinguish from CNA              |

The public record corpus includes `PUBLISHED` and `REJECTED` formats. It does not
enumerate all unpublished reserved IDs. Ordinary counts/rankings use `PUBLISHED`;
record rejection and corrections must update derived views. Some historical dates
have known issues documented in the README. Metrics, titles, languages, products and
aliases are not universally populated; never turn absence into a zero score.

Distribution choices:

- Git snapshot plus changed-path diff between imported commits: implemented workflow.
- Daily full baseline ZIP plus hourly **cumulative changes since that baseline**:
  alternative, not independent previous-hour deltas.
- Rolling `delta.json` / `deltaLog.json`: not a permanent transaction log. Retention
  can change during maintenance; gaps require full reconciliation.

At day rollover, pair each release delta with the matching dated baseline. If a
baseline/checkpoint is missing, history has expired or continuity cannot be proven,
fetch a fresh complete baseline. See [workflow](../DATA_WORKFLOW.md) for the implemented contract.

## CISA KEV Contract

First-party evidence: [catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
[license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt),
[official mirror and license](https://github.com/cisagov/kev-data).

The license says: "The KEV database is distributed under the Creative Commons 0 1.0
License. You may use this data in any legal manner." Linked third-party content keeps
its own terms. This grants neither use of CISA/DHS marks nor implied endorsement.

Anonymous HTTPS GET returns a full snapshot. Relevant fields are `catalogVersion`,
`dateReleased`, `count`, and `vulnerabilities[]`; entries include `cveID`, `dateAdded`,
`vendorProject`, `product`, `shortDescription`, `requiredAction`, `dueDate`,
`knownRansomwareCampaignUse`, `notes` and `cwes`. Keep the source metadata and optional
new fields without presuming every field is present across historical snapshots.

Membership means included in this curated known-exploitation catalog. Absence means
**not listed in the accepted snapshot**, not proof of no exploitation. `dateAdded` is
catalog-entry date, not necessarily the first exploit date. Update the accepted full
snapshot atomically after validating counts/IDs. No polling/freshness SLA was found.

## FIRST EPSS Contract

First-party evidence: [data access](https://www.first.org/epss/data),
[FAQ](https://www.first.org/epss/faq), [API](https://api.first.org/epss/),
[services terms](https://www.first.org/about/policies/terms),
[history](https://github.com/empiricalsec/epss_scores).

FIRST says scores are "published daily, free of charge, with no registration required."
The FAQ requests attribution in products/publications. The services terms grant a
limited, revocable license for distribution "only for vulnerability disclosure,
cybersecurity incident response, or preventative cybersecurity uses" with notices
retained. A preventative dashboard appears aligned; blanket permission for every
commercial arrangement is **not established**. Seek clarification before monetizing.

| Access                                                              | Contract                                                                               |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `GET https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Follow redirects; full daily bulk snapshot; preferred for local corpus synchronization |
| `GET https://api.first.org/data/v1/epss?cve=<ID>`                   | Public lookup/small batches; not a bulk-sync mechanism                                 |
| Historical daily files in linked repository                         | Needed for genuine dated comparisons; availability is not unlimited API throughput     |

CSV columns are `cve,epss,percentile`. Read the leading comment for `model_version`
and `score_date`. API rows include `cve`, `epss`, `percentile`, `date`.
`epss` is a 0-1 forecast of observed exploitation activity over the next 30 days;
`percentile` is a relative position among scored CVEs. Neither is social popularity,
severity, an exploit count, or organization-specific risk.

Historical files begin in 2021. Model changes can move scores without changed CVE
conditions: do not interpret a cross-model jump as rising threat. A missing current
row is unknown, not zero and not permission to silently reuse yesterday's score.
Partner exploitation telemetry behind the model is not redistributed by this feed.

## Live Evidence Log

Checked without keys on 2026-10-24:

- [CVE sample](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/109xxx/CVE-2026-109618.json)
  returned HTTP 200 and JSON; published state/date and description previously parsed
  in this audit series. This is a sample, not a full-corpus completeness test.
- Official KEV JSON parsed: catalog `2026.10.23`, released `2026-10-23T19:30:18.9209Z`;
  declared count, actual rows and unique IDs each **1,756**. This snapshot also has
  `forensicTriage`, illustrating schema evolution.
- Full EPSS download parsed at **2026-10-24T03:57:03.263Z**: model `v2026.06.15`, score
  date `2026-10-23T12:00:28Z`; **394,803 rows and unique IDs**, **0 invalid rows** under
  checks for column shape, CVE-ID syntax, duplicate IDs, finite numeric values and
  0-1 ranges. This is structural validation, not independent model validation.
- EPSS compressed bytes **2,767,303**, decompressed bytes **12,002,809**; compressed
  SHA-256 `a92f4b9f28006420a11db24c50c9e30290f9b54884c48fca9e87bf936d68cb62`.
  That hash identifies the downloaded bytes, not a publisher signature.
- Sample `CVE-2026-109618`: `epss=0.1162`, `percentile=0.96047` in that CSV; API lookup
  also returned successfully. Values are dated observations, not enduring facts.
- Additional direct raw-record reads for `CVE-2026-109618` and `CVE-2026-109619`
  showed a CNA CVSS v4.0 base **9.2** for each. Their CISA-ADP metrics included SSVC,
  not a CVSS metric. This checks representative primary-metric availability, not
  corpus-wide coverage or a guarantee that they lead an automated ranking.

No full CVE bulk import, local database/search benchmark, production hosting cost,
cross-source join completeness measurement, or long-running sync test has been run.

## Feature Limits and Launch Obligations

These sources support records, counts, text search and explainable exploitation
priority with missing-data handling. They do **not** establish social popularity,
universal aliases/CVSS, complete reserved counts or real-time exploitation telemetry.
Before release: reproduce required notices, approve the cybersecurity-use scope,
measure coverage/operations, verify link/excerpt behavior, and recheck changed terms.
Optional NVD or other enrichment needs its own documented access/reuse review.
