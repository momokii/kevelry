# Competitor Verification

Checked: 2026-10-24. Scope: public pages without sign-in, not a service-quality audit.
Comparison requirements: overview charts, prioritized CVEs with explained scoring,
search/filter, short descriptions and links to upstream records.

## Method and Limits

Researchers retrieved first-party pages and representative search/detail URLs.
Browser-rendered checks were **not run: Chromium was unavailable**; nothing was
installed. Retrieved labels/canvases do not prove chart rendering or interactive
controls work. A blocked page means **unverified**, not absent functionality.

Evidence labels: **Observed** = retrieved result/content; **Claimed** = first-party
feature/plan description; **Unverified** = inaccessible or not exercised.

## Comparison

| Website | Overview | Top/ranking | Search and descriptions | Method / access | Fit |
|---|---|---|---|---|---|
| [o2CVE](https://o2cve.com/) | Observed [statistics and methods](https://o2cve.com/stats); visual rendering unverified | Observed priority list and [formula](https://o2cve.com/method) | Observed [PHP query](https://o2cve.com/cve?q=php), excerpts, filter labels and exact CVE detail | Public content; [API page](https://o2cve.com/api) claims free lookup and daily bulk exports | Substantial overlap; closest verified alternative |
| [Osprey](https://cve.0xosprey.com/) | Observed chart controls/source attribution; fetched page still says Loading | No top list or formula verified on inspected page | No per-record search/description workflow verified on inspected page | Public page and [raw JSON link](https://cve.0xosprey.com/data.json); reuse/API terms unverified | Relevant overview reference, not a verified combined workflow |
| [CVEFeed](https://cvefeed.io/) | Analytics charts not verified on retrieved landing page | Prioritization signals claimed; transparent ranking formula not verified | Monitoring/alert filters claimed; public browse/search flow not tested | Free/paid plans and token API claimed on landing page | Different monitoring emphasis; not verified equivalent |
| [CVEDetails](https://www.cvedetails.com/) | Unverified | Unverified | Unverified | HTTP 403 from research client | Cannot conclude feature absence |
| [NVD search](https://nvd.nist.gov/vuln/search) | Unverified in this check | Unverified | Search URL returned HTTP 403 | Separate official data service; no current access/reuse review in this audit | Cannot conclude feature absence |
| [CVEStream](https://www.cvestream.io/dashboard) | Retrieved counters and disclosure/severity summaries | Latest disclosures observed; priority formula unverified | Retrieved CVE IDs/descriptions; search/filter unverified | Freshness/source claims observed; API/pricing unverified | Partial overlap; insufficient evidence of combined features |

## o2CVE Checks

- `GET /`, `/stats`, `/method`, `/cve?q=php` and `/api` returned public content.
- [PHP search](https://o2cve.com/cve?q=php) returned a 10,000-result count, actual CVE
  IDs, excerpts, scores, signals and dates. Vendor/product, date, risk, score,
  exploitation and weakness filter labels were observed; browser submission was not.
- [Exact-ID query](https://o2cve.com/cve?q=CVE-2026-109618) resolved to the canonical
  [detail page](https://o2cve.com/cve/CVE-2026-109618) during the parent verification.
  The retrieved page displayed summary, version/product data, source references,
  score breakdown, CVSS, EPSS and provenance. Score then displayed **94/100**.
- Upstream vendor/advisory references were observed. A consistent dedicated
  CVE.org-record outbound link for every result was **not verified**.
- [Statistics](https://o2cve.com/stats) includes exploitation/KEV-delay distributions,
  vendor/weakness summaries, monthly information, and method/denominator notes.
- [Method](https://o2cve.com/method) describes additive points, capped at 100:
  CVSS times 4, EPSS percentile times 25, and exploitation/alert/exposure factors.
  This is the site's own heuristic, not validation that it measures calibrated risk.
- [API documentation](https://o2cve.com/api) claims 60 requests/hour/IP without a key,
  1,000/day with a free key, feeds and daily compressed JSONL/CSV. Quotas and bulk
  completeness were not independently benchmarked. A public API is not automatically
  a reuse license for every upstream datum or derived field.

## Other Checks

- Osprey home returned HTTP 200, chart-control labels and CVE List V5 attribution;
  raw data was linked. Chart quality and controls were not browser-tested. Lack of
  verified search on that page is not a claim about all Osprey properties.
- CVEFeed home returned HTTP 200. Its landing page claimed a $0 Free plan with
  project/subscription limits and API/CVEQL quotas, plus paid tiers. No account,
  token, alert or paid feature was used; do not base this project's source plan on it.
- CVEDetails home and NVD search returned HTTP 403. No bypass or login attempted.
- CVEStream dashboard retrieval showed latest disclosures and summary text; no
  interactive/visual/complete-data or scoring guarantee follows from that response.

## Build-versus-Use Verdict

**The concept already exists.** o2CVE substantially overlaps the requested feature
combination. Try it first if the goal is simply to consume the information.
Building is still reasonable for a simpler experience, transparent local snapshots,
independent ownership, or a narrower source/ranking policy. Those are product goals,
not evidence that existing tools are deficient or that this is a unique category.

Do not scrape these services to assemble the MVP. Prefer the direct upstream
sources audited in [SOURCES.md](SOURCES.md). Before a public launch, repeat browser
checks when tooling is available and recheck competitor terms/features. This audit
does not establish anyone's corpus completeness, continuous freshness or uptime.
