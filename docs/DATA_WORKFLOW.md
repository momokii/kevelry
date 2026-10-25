# Data Workflow and Ranking Contract

**PROPOSED: owner approval pending.** These are candidate product policies, not
approved architecture or validated risk science. No framework, database or host is
selected. See [feasibility](../FEASIBILITY.md), [source audit](research/SOURCES.md)
and [competitor audit](research/COMPETITORS.md) for evidence and limitations.

## Scope and Field Mapping

Use locally imported CVE List V5, CISA KEV and FIRST EPSS. Visitor-facing search and
lists read local data, not upstream APIs. No paid model or generated summary is needed.
Default search and all ranked views include only current `PUBLISHED` CVE records.

| Feature                | Proposed input and treatment                                                                                                                                     |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/text search         | Validated ID, supplied title, descriptions and supplied product/vendor labels; local text index, no guaranteed nickname matching                                 |
| Description excerpt    | Prefer first `en`/`en-*` CNA description in source order; otherwise first supplied description with language label; missing text says "Description not supplied" |
| Title                  | Supplied CNA title, otherwise CVE ID; do not invent an advisory name                                                                                             |
| Official link          | Build `https://www.cve.org/CVERecord?id=<CVE-ID>` from validated ID; no dedicated local detail page required                                                     |
| Published-volume chart | Publication timestamp and current state, not year encoded in ID; UTC calendar buckets                                                                            |
| KEV and EPSS views     | Exact-ID joins, with source dates, model and join coverage shown                                                                                                 |
| Severity filters       | Primary CNA metric policy below; unknown/legacy explicitly separate                                                                                              |
| Rising forecast        | Two dated EPSS probabilities from the same model; not social attention                                                                                           |

Descriptions remain original upstream text. A display excerpt is at most 320 Unicode
code points plus an ellipsis if shortened; preserve full text locally and render as
plain text. Language fallback is not a translation. Escape output and retain provenance.
Curated aliases/spotlights are optional future editorial data, not upstream guarantees.

For date filters use UTC `[start, end)` intervals. Daily/monthly cumulative charts
are retrospective counts under the accepted current records; corrections/rejections
can change historical totals. Missing publication dates go to an explicit unknown
bucket and are excluded from dated buckets, with coverage shown. Do not estimate all
unpublished reservations, annual counts from ID numbers, or total worldwide exploitation.
Keep syntactically valid source dates unchanged even when the source documents a
historical anomaly; annotate known affected cohorts and link the source issue/note.
Do not locally guess corrected dates or substitute reservation/ID-year dates. Rebucket
only after an upstream correction, recording the old/new source revision. Invalid
date syntax fails import validation; a documented semantic anomaly is a distinct flag.
Severity distributions show version groups and unscored counts/denominators; an
unscored CVE is not low severity. Do not imply different CVSS versions are calibrated alike.

## CVE Ingestion Proposal

1. Pin a Git revision of CVE List V5. Read CVE record files in the full `cves/`
   tree at that revision; exclude repository metadata/delta manifests from the
   record-file enumeration. Save upstream repository identity and revision.
   The runtime image bundles `git` plus CA certificates so this clone/fetch
   refreshes in-container over HTTPS; the first refresh clones a large
   repository (gigabytes, minutes), and the worker logs a `source-start` line per source before its
   job runs plus runs at a lower OS priority so web requests win contention.
   The checkout is a persistent cache at `<DATA_DIR>/cve-repo` (override with
   `CVE_REPO_DIR`): first run clones shallow (`CVE_CLONE_DEPTH`, default 1),
   later runs `git fetch` incrementally in that same single working tree and
   diff against the last imported SHA, so refreshes never re-clone and the
   import never holds two full checkouts at once. The cache is never deleted
   automatically; a corrupt (non-repo) directory is re-cloned with a
   `cve-cache-corrupt-reclone` log line, and `CVE_REPO_CACHE_RESET=true`
   forces a clean re-clone. Expected disk: ~5-6 GB shallow; every cycle logs
   `cve-cache-size` with the measured bytes.
2. For incremental imports, fetch upstream and pin the next revision. Compare it
   with the last successfully imported revision; enumerate added, changed and deleted
   paths, reading candidate files from the new revision rather than a moving branch.
3. Apply changes idempotently. Rejections leave ordinary lists/counts; deletions
   leave the current dataset. Retain provenance/tombstones for explaining changes.
4. If the previous revision is unavailable, history discontinuous, or continuity
   cannot be established, reconcile the complete pinned tree. Do not publish a
   partial changed-file result as a full corpus.
5. Validate and stage the resulting complete local dataset before publishing its
   revision. Parse and stage the corpus in bounded batches (session-scoped
   staging tables, one bounded transaction per batch), then merge into the live
   tables in a single final transaction so partial state is never visible.
   A successful import is the only event that advances the import checkpoint.

**Alternative: release assets.** Seed a dated full baseline and track its identity.
Hourly assets are cumulative since that baseline, not independent prior-hour events.
Reapplication must be idempotent. At day rollover, establish the matching new baseline
before applying its delta; recover missed days/expired history via a fresh baseline
and reconciliation. An hourly delta does not prove all intermediate historical events.
Do not mix unrelated baselines or require an expired rolling delta log for recovery.

## KEV and EPSS Ingestion

- Import KEV as a complete validated catalog snapshot. Validate declared/actual
  counts, unique valid IDs, required fields and catalog date/version. Replace current
  membership only after validation; removal means not in the new catalog, not no
  historical exploitation. Save membership history separately from the current flag.
- Import EPSS as a complete daily CSV. Read its comment metadata, require expected
  columns, validate ID uniqueness and finite numeric probabilities/percentiles in
  `[0,1]`, and retain exact source decimals, score date and model version.
- Use one accepted EPSS date/model for current comparisons; a missing current row
  is unknown. Do not fill it invisibly from an older date. Real zero remains known.
- Store unmatched KEV/EPSS IDs and report join coverage; do not manufacture CVE
  records to satisfy a join. CVE-source updates can later resolve an unmatched ID.
- Historical analysis uses dated historical files or retained daily observations,
  never the assumption that the moving current-file URL preserves past versions.

## Validation and Publication

Validate records with the matching declared `dataVersion` schema. Accept known
supported valid versions; an unsupported version is an explicit failed/quarantined
import, not silently discarded content. Preserve all raw containers/provider fields.
Malformed present IDs, structures or numbers fail validation; absent optional
values remain unknown. ISO-8601 datetimes without a timezone suffix are accepted
and interpreted as UTC; other malformed timestamps fail validation. Record files
larger than the per-record cap (default 16 MiB, `CVE_MAX_RECORD_BYTES`) are
quarantined. A quarantined set at or below max(50, 0.1% of scanned records) is
tolerated: the good records publish, and the quarantine list, count, and reasons
are stored in `sync_runs` and logged as a structured warning. Above that ceiling
the import fails closed: last-known-good data is preserved and the import
checkpoint does not advance. Record anomalies and coverage without inventing values.

Each source refresh is independent. Build an immutable local publication manifest that
references accepted CVE/KEV/EPSS versions. Advance valid sources atomically while
retaining any failed source's last-known-good snapshot, with a visible stale/error
flag. One failed source must not freeze unrelated successful source updates. Initial
publication requires an accepted snapshot of each core source; no missing feed is
substituted with fabricated zeros or empty memberships.

Daily observed checkpoints retain bounded observed lists, not complete
enumerations: each materialized view holds at most `CHECKPOINT_TOP_N` entries
(default 500, env-overridable and validated) built through the limit-aware
ranking getters, with per-record snapshots kept only for retained IDs. The
manifest records the applied bound as `boundedTopN` alongside the full
eligible cohort count and cohort identity; replay responses surface
`boundedTopN` with an explicit bounded-list notice so a replay never implies
completeness. Bounding keeps the daily write to seconds and the payload to
kilobytes on a full-size corpus instead of pinning the worker and starving
request handling.

Retain source URI, revision/version/date, retrieval time, content hash, validation
status, last attempt, last successful check, last accepted import and error status.
A locally computed hash identifies bytes; it is not a publisher authenticity signature.
Reimporting identical bytes/revision yields the same normalized result without duplicates.
A successful unchanged check updates health, not record-modified dates.

## Primary CVSS Proposal

This is a deterministic editorial selection for one displayed metric, not an
official reconciliation of providers. Preserve every original metric for inspection.

1. Consider valid original CNA CVSS base metrics only for the primary metric.
2. Prefer version 4.0, then 3.1, then 3.0, then 2.0.
3. Within the chosen version, choose the highest published base among scenarios,
   explicitly labeled "worst CNA-provided scenario"; tie-break by vector ASCII ascending.
4. If score/vector tie, retain scenario/source order as the final deterministic tie.
5. Preserve and distinguish all other CNA and ADP metrics, source/provider, version,
   vector and scenario. ADP-only scores are visible as secondary metrics, not silently
   promoted by this policy. No valid CNA metric means unknown primary.

CVSS v2-only is legacy-scored and is not called critical. Modern primary v3/v4
base >=9 qualifies for the proposed new-critical view. This deliberately limits
coverage; NVD or ADP-based enrichment needs an approved revised selection policy.

## Ranking Proposal v1

No custom 0-100 composite is produced. Multiplying CVSS by EPSS or combining them
with arbitrary weights does not create a calibrated probability or risk score.
This site proposes explainable ordering and displays existing source scores.

For all views first join against current `PUBLISHED` CVEs. Missing optional values
are explicitly unknown; sort raw, unrounded source values, not formatted display text.
Probability/delta comparisons use exact source-decimal arithmetic: binary floating
point subtraction must not break a mathematically equal-delta tie. Round for display only.

**Default priority** compares these keys in order, stopping at the first difference:

1. KEV member before not listed in accepted KEV snapshot.
2. Within that tier, EPSS present before unknown.
3. Within scored records, EPSS probability descending (actual zero remains scored).
4. Known publication timestamp before unknown.
5. Publication timestamp descending.
6. CVE ID ASCII ascending.

**Known exploited:** KEV members, `dateAdded` descending then ID ASCII ascending.
This date is catalog addition, not proven first exploitation or current attack volume.

**Highest forecast:** known EPSS, raw probability descending, known publication before
unknown, publication descending, ID ASCII ascending. Display score date and model.
`display_probability_percent = 100 * epss`; `display_percentile = 100 * percentile`.
A 96th percentile is not a 96% exploitation probability.

**New critical:** let `T` be stored UTC publication cutoff. Include publication times
in `[T - 30*24h, T)` and primary modern CVSS >=9.0. Order publication descending,
then ID ASCII ascending. Unknown, legacy-only and ADP-only primary cases are ineligible,
not low severity. No mixed-version numeric severity ordering is implied.

**Rising forecast:** let `d` be the accepted current EPSS UTC score date. Require
observations on exactly `d` and `d-7` calendar days with the same model version.
`delta_pp = 100 * (epss[d] - epss[d-7])`. Include positive changes only; sort delta
descending, current raw probability descending, ID ASCII ascending. Missing dates
and model transitions are ineligible, not zero or interpolated data. This is a
forecast movement list, not social popularity or observed exploitation telemetry.

Stale source data retains its dated values and stale label; it is never relabeled
as a current-day forecast. A headline CVE is not guaranteed to rank first. Optional
editorial spotlighting must be labeled and separate from this automated ordering.

## Worked Examples

Synthetic IDs/values below are invented, not claims about real vulnerabilities.
Assume publication timestamps equal/known except where stated.

| Case                       | Inputs                                                                    | Required outcome                                                          |
| -------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Evidence tier dominates    | `CVE-2099-0001`: KEV, EPSS unknown; `CVE-2099-0002`: not listed, EPSS .99 | 0001 first despite missing score                                          |
| Probability within a tier  | Two nonmembers, p .80 vs .20; the .20 record is newer                     | .80 first; publication recency does not override p                        |
| Zero vs unknown            | 0003 not listed, EPSS 0; 0004 not listed, unknown                         | 0003 first; do not coerce unknown to 0                                    |
| Display rounding           | 0005 EPSS .12344; 0006 .12341; both display 12.34%                        | 0005 first using raw probability                                          |
| Complete numeric/date tie  | 0007 and 0008 share tier, p and publication timestamp                     | 0007 first by ASCII ID                                                    |
| Known vs missing date      | 0010 dated, 0011 undated; same tier/p                                     | 0010 first                                                                |
| Timestamp tie-break        | Same tier/p, publication 23 Oct vs 22 Oct                                 | 23 Oct first                                                              |
| KEV-specific ordering      | Listed dates 23 Oct vs 22 Oct; the older entry has greater EPSS           | 23 Oct first in known-exploited view; EPSS is not its sort key            |
| Forecast-specific ordering | A nonmember p .90 vs KEV member p .10                                     | .90 first in highest-forecast view; KEV is not its sort key               |
| CNA source policy          | ADP v4 10.0 exists but no valid CNA metric                                | Primary unknown; secondary retained; new-critical ineligible              |
| Version preference         | CNA v4 8.5 and CNA v3.1 9.8                                               | Primary v4 8.5, new-critical ineligible under this policy                 |
| Scenario and vector ties   | Same preferred version: 9.2 vs 8.5; equal 9.2 vectors B vs A              | Choose 9.2, then vector A; final equal-vector tie uses source order       |
| Legacy-only metric         | CNA v2 10.0 only                                                          | Legacy-scored, not critical                                               |
| Rising calculation         | Model A on both dates, p .10 then .18                                     | +8 percentage points, not +80 percentage points                           |
| Rising ties                | Same model: .10 to .18 and .20 to .28                                     | Equal +8-point delta; .28 current p first, then ID if current p also ties |
| Model boundary             | Model A p .10, model B p .80                                              | Ineligible for rising; no +70-point spike claim                           |
| Missing history            | Current p known, no exact d-7 row                                         | Ineligible; do not substitute nearest day or 0                            |
| Date boundary              | CVSS 9.8 modern; published at T-30d vs exactly T                          | First included, second excluded                                           |
| New-critical order         | Two eligible records, different publication times                         | Newer first; equal timestamp uses ID, not CVSS magnitude                  |

## Freshness Proposal

Proposed schedules: CVE hourly; KEV hourly with conditional requests where supported;
EPSS daily after expected publication. These are our targets, not upstream SLAs.
Flag CVE/KEV when last successful check is **more than 3 hours** old, even if unchanged.
Do not flag an old vulnerability merely because its record has not changed.
Flag EPSS when its accepted score date is **older than 2 UTC calendar days**.
Keep last-known-good data with visible per-source timestamps and errors during outages.

## Security and Acceptance Gates

Treat upstream text/URLs/archives as untrusted. Validate bounded input/schema,
parameterize local queries, encode output, and allow only safe web URL schemes for
reference links. Do not fetch arbitrary record URLs server-side or execute PoCs.
If archives are used, constrain entry paths/counts, expanded size and compression
ratio; reject traversal, symlinks and decompression bombs. Hash/log metadata, not secrets.

Before website implementation, owner approval is required for scope, source-use
purpose, these ranking/missing-data policies, stack and hosting. Before launch:

- Test imports: same revision twice, add/change/delete/reject, history gap, day
  rollover, missed EPSS day, model transition, unmatched joins and failed source.
- Verify failed refreshes preserve last-known-good data and do not freeze valid feeds.
- Test all worked ranking examples, unknown values, exact cutoffs and source provenance.
- Test language/missing excerpts, local-only search, ID links, unsafe text and URLs.
- Approve benchmark targets **before** running them: corpus revision/size, resources,
  import durations, storage/peak memory, query mix/concurrency and search latency.
- Measure full CVE import, coverage, sustained incremental recovery and actual hosting
  cost. None of these operational results has been measured in this documentation pass.

The full EPSS structural check in the source audit is not a full application benchmark.

## Documentation Verification

On 2026-10-24, an in-memory synthetic driver passed **31 assertions** covering
the proposed view orders, CVSS selection, known-zero versus missing values, decimal
ties, exact cutoff dates, missing history and model transitions. Fixtures used exact
scaled integers for probability arithmetic, not rounded display values. This checks
documented examples, not a production ingestion/search implementation.

Local Markdown file targets and fenced-code balance were checked across the four
audit documents with no broken local file links. Markdown LSP diagnostics were
unavailable because no Markdown language server is configured. A single read-only
reviewer rechecked corrected feature coverage, date anomalies and ranking examples;
no further material findings remained in those checks. Launch gates above remain open.
