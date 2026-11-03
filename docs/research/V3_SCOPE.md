# v3 scope: researched 2026-11-01

Question: what would be a genuinely major next step for this app, given the
current contract (read-only, anonymous, single image, free feeds only, no
composite score, unknown stays unknown)?

## Verified live (this session)

| Source                                     | Check                           | What it yields                                                                                                                                                                                                       |
| ------------------------------------------ | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cisagov/vulnrichment` (GitHub)            | repo metadata + sampled records | **CC0-1.0**, ~380 MB repo, per-CVE JSON at `YYYY/<prefix>xxx/CVE-….json`, ADP containers carrying **CISA SSVC** decision points (`Exploitation` active/poc/none, `Automatable`, `Technical Impact`) and **ADP CVSS** |
| `api.github.com/advisories`                | 200, keyless                    | GHSA records with **CWE ids + names**, `cvss_severities`, references                                                                                                                                                 |
| `api.osv.dev/v1/query`                     | 200, keyless                    | Affected version ranges (`introduced`/`fixed`) per ecosystem                                                                                                                                                         |
| `services.nvd.nist.gov/rest/json/cves/2.0` | 200, keyless                    | `cpeName` matching, NVD CVSS, CWE assignments                                                                                                                                                                        |

Coverage is partial by design: Vulnrichment does not cover every CVE (two of
three sampled records were absent), so any feature must degrade to "not
enriched", never to a guess.

## The big one: CISA SSVC overlay

**Why it is major.** Today the product shows three raw signals and refuses to
combine them. SSVC is the one combination that is _not ours to invent_: CISA
publishes the decision points, and the resulting decision (Track / Track* /
Attend / Act) is their methodology, not a home-made score. That squares the
circle — explainable prioritisation without a composite score.

- Inputs: `Exploitation`, `Automatable`, `Technical Impact` (all published).
- Output: a decision label, with the three inputs shown beside it.
- Labelling rules: only on records Vulnrichment covers; everything else says
  "no SSVC published", never "Track".

**Status 2026-11-03:** items 1 and the `ssvc-active` view are now shipped in
this codebase (see `docs/DATA_WORKFLOW.md`). Coverage observed live: 201
KEV-listed records with `Exploitation = active` out of 1,766 KEV rows — partial
by design, and reported as such in the UI.

## Ranked recommendations

1. **SSVC overlay** (High impact / Medium effort). New importer on the same
   git-cache pattern as CVE List V5; migration adds `ssvc_*` columns; a fourth
   priority view `kev-ssvc-act` is arguably _the_ reason to visit the site.
2. **ADP CVSS for unscored records** (High / Small). 215k published records
   are "unscored" today because CNA metrics are missing. Vulnrichment supplies
   ADP scores for a slice of them. Rule: keep CNA primacy, add a clearly
   labelled secondary value, and never merge them into one number.
3. **Time-to-exploitation analytics** (High / Small, no new feed). We already
   hold `date_published` and KEV `dateAdded`. The lag distribution — "how long
   from publication to confirmed exploitation" — is a genuinely new question
   the app can answer from its own retained data, with a named denominator.
4. **CWE taxonomy** (Medium / Medium). Names + mitigations from the MITRE pack
   (`cwec_latest.xml.zip`, verified reachable) turn `CWE-94` into "Code
   Injection" with prevention guidance. Needs an XML parser dependency.
5. **Bulk API** `GET /api/v1/cves?ids=…` (Medium / Small). Integrators
   currently fan out one request per CVE; the watch page already does this.
6. **Radar as RSS** (Medium / Small). Anonymous alerting that fits the
   no-accounts design.
7. **Vendor/CWE concentration dashboards** (Medium / Medium). "Which vendors
   own the exploited corpus" — same aggregate-cache pattern, new insight.

## Explicitly not doing

- **Accounts, watchlists server-side, email alerts** — breaks anonymous-by-design.
- **3D graph** — breaks keyboard access and readability for no analytic gain.
- **Third-party news feeds** — CISA RSS is bot-walled from here and reuse
  terms are unclear; a rotting news box costs more trust than it buys.
- **Exploit how-to content** — safety stance, unchanged.
- **LLM summaries** — a fluent paragraph invents connective tissue, violating
  the no-estimation contract.

## Sequencing if approved

SSVC (1) → ADP CVSS (2) → time-to-exploitation (3). Each is its own commit
with the same fallback discipline as the current three feeds: last-known-good,
per-source stale flags, and an explicit "not published" state.
