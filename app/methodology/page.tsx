// Methodology and data-status page (plan todo 23). Server component reading
// the accepted local snapshots through `buildProvenance` (the same sync_runs
// health the versioned API reads), so per-source Current/Stale/Source
// failed/Missing states match the API exactly. All reuse notices below are
// copied from docs/research/SOURCES.md and FEASIBILITY.md. This page gives
// no legal advice and makes no completeness claims: gaps stay visible.

import { PageHeader } from "@/components/shell/PageHeader";
import path from "node:path";

import { buildProvenance, RANKING_POLICY_VERSION } from "@/app/api/v1/_lib/shared";
import { HelpTip } from "@/components/ledger/HelpTip";
import { TimeText } from "@/components/ledger/TimeText";
import { OrderingDiagram } from "@/components/methodology/OrderingDiagram";
import { PipelineExplorer } from "@/components/methodology/PipelineExplorer";
import { CoverageDiagram } from "@/components/methodology/CoverageDiagram";
import { ScoringExample } from "@/components/methodology/ScoringExample";
import { SignalDiagram } from "@/components/methodology/SignalDiagram";
import styles from "@/components/methodology/MethodologyDiagrams.module.css";
import { getAggregates, severityBandsSql } from "@/lib/aggregates";
import { openReadDatabase, type CveDatabase } from "@/lib/db";

export const revalidate = 60;

export const metadata = {
  title: "Methodology — CVE Intel",
  description:
    "What CVSS, KEV, and EPSS mean, exact ordering rules, source dates and reuse notices, coverage gaps, and per-source health.",
};

function resolveDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") {
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
  }
  return path.join(process.cwd(), "data");
}

function countQuery(db: CveDatabase, sql: string): number | null {
  try {
    const row = db.handle.prepare(sql).get() as Record<string, unknown> | undefined;
    const value = row === undefined ? null : Object.values(row)[0];
    return typeof value === "number" ? value : null;
  } catch {
    return null;
  }
}

interface HealthLine {
  key: "cve" | "kev" | "epss";
  name: string;
  symbol: string;
  label: string;
  detail: string;
  warning: string | null;
}

export default function MethodologyPage() {
  const nowIso = new Date().toISOString();
  let provenance = buildProvenance(null, nowIso);
  let publishedTotal: number | null = null;
  let kevListed: number | null = null;
  let epssScored: number | null = null;
  let unknownDates: number | null = null;
  let cnaScored: number | null = null;
  let loadError: string | null = null;

  try {
    const db = openReadDatabase(resolveDataDir());
    provenance = buildProvenance(db, nowIso);
    const cached = getAggregates(db);
    if (cached !== null) {
      publishedTotal = cached.totals.published;
      kevListed = cached.totals.kev;
      epssScored = cached.totals.epssScored;
      unknownDates = cached.totals.unknownDate;
      const bands = cached.severityBands;
      cnaScored =
        (bands.critical ?? 0) +
        (bands.high ?? 0) +
        (bands.medium ?? 0) +
        (bands.low ?? 0) +
        (bands.none ?? 0) +
        (bands.legacy ?? 0);
    } else {
      publishedTotal = countQuery(
        db,
        "SELECT COUNT(*) AS n FROM cve_records WHERE state = 'PUBLISHED'",
      );
      kevListed = countQuery(db, "SELECT COUNT(DISTINCT cve_id) AS n FROM kev_entries");
      epssScored = countQuery(db, "SELECT COUNT(DISTINCT cve_id) AS n FROM epss_daily");
      unknownDates = countQuery(
        db,
        "SELECT COUNT(*) AS n FROM cve_records WHERE state = 'PUBLISHED' AND date_published IS NULL",
      );
      const bands = severityBandsSql(db);
      cnaScored =
        (bands.critical ?? 0) +
        (bands.high ?? 0) +
        (bands.medium ?? 0) +
        (bands.low ?? 0) +
        (bands.none ?? 0) +
        (bands.legacy ?? 0);
    }
  } catch (error) {
    loadError = error instanceof Error ? error.message : String(error);
  }

  const sources = provenance.sources;
  const lines: HealthLine[] = [
    {
      key: "cve",
      name: "CVE List V5",
      symbol: sources.cve.error !== null ? "!" : sources.cve.stale ? "~" : "=",
      label:
        sources.cve.error !== null
          ? "Source failed"
          : sources.cve.lastAcceptedAt === null
            ? "Missing"
            : sources.cve.stale
              ? "Stale"
              : "Current",
      detail: `Revision ${sources.cve.revision ?? "unknown"}, last accepted ${sources.cve.lastAcceptedAt ?? "not recorded"}, last checked ${sources.cve.lastCheckedAt ?? "not recorded"}.`,
      warning:
        sources.cve.error !== null
          ? `Refresh failed: ${sources.cve.error}. Serving last-known-good records with this warning. One failed source never freezes the other successful updates.`
          : sources.cve.stale
            ? "Last successful check is more than 3 hours old. Dated values are retained with this label."
            : null,
    },
    {
      key: "kev",
      name: "CISA KEV",
      symbol: sources.kev.error !== null ? "!" : sources.kev.stale ? "~" : "=",
      label:
        sources.kev.error !== null
          ? "Source failed"
          : sources.kev.lastAcceptedAt === null
            ? "Missing"
            : sources.kev.stale
              ? "Stale"
              : "Current",
      detail: `Catalog dated ${sources.kev.catalogVersion ?? "unknown"}, last accepted ${sources.kev.lastAcceptedAt ?? "not recorded"}, last checked ${sources.kev.lastCheckedAt ?? "not recorded"}.`,
      warning:
        sources.kev.error !== null
          ? `Refresh failed: ${sources.kev.error}. Serving last-known-good membership with this warning. One failed source never freezes the other successful updates.`
          : sources.kev.stale
            ? "Last successful check is more than 3 hours old. Dated values are retained with this label."
            : null,
    },
    {
      key: "epss",
      name: "FIRST EPSS",
      symbol: sources.epss.error !== null ? "!" : sources.epss.stale ? "~" : "=",
      label:
        sources.epss.error !== null
          ? "Source failed"
          : sources.epss.scoreDate === null
            ? "Missing"
            : sources.epss.stale
              ? "Stale"
              : "Current",
      detail: `Score date ${sources.epss.scoreDate ?? "unknown"}, model ${sources.epss.modelVersion ?? "unknown"}, last accepted ${sources.epss.lastAcceptedAt ?? "not recorded"}, last checked ${sources.epss.lastCheckedAt ?? "not recorded"}.`,
      warning:
        sources.epss.error !== null
          ? `Refresh failed: ${sources.epss.error}. Serving last-known-good forecasts with this warning. Stale forecasts keep their dated values and are never relabeled as current-day forecasts.`
          : sources.epss.stale
            ? "Accepted score date is older than 2 UTC calendar days. Dated values are retained with this label; they are never relabeled as current-day forecasts."
            : null,
    },
  ];

  return (
    <main className="page" data-testid="methodology-root" id="main-content">
      <PageHeader
        eyebrow={
          <>
            <span>Method</span>
            <span className="dot" aria-hidden="true" />
            <span>signals, pipeline, ordering</span>
            <span className="dot" aria-hidden="true" />
            <span>policy {RANKING_POLICY_VERSION}</span>
          </>
        }
        title="How the data works"
        lede={
          <span data-testid="methodology-lede">
            How CVEs are ordered, where every value comes from, what is missing, and whether each
            source is healthy. Checked 2026-10-24; these are dated findings, not legal advice.
          </span>
        }
        actions={
          <a className="btn btn-sm" href="/api-docs">
            API reference
          </a>
        }
      />
      <p className="chart-note" data-testid="methodology-generated">
        Page generated <TimeText value={nowIso} testId="methodology-generated-time" />.
      </p>

      <nav
        aria-label="Methodology sections"
        data-testid="methodology-anchor-nav"
        className={styles.anchorNav}
      >
        <ul className={styles.anchorNavList}>
          <li>
            <a href="#methodology-section-signals">Signals</a>
          </li>
          <li>
            <a href="#methodology-section-coverage">Coverage</a>
          </li>
          <li>
            <a href="#methodology-section-pipeline">Pipeline</a>
          </li>
          <li>
            <a href="#methodology-section-ordering">Ordering</a>
          </li>
          <li>
            <a href="#methodology-section-example">Example</a>
          </li>
          <li>
            <a href="#methodology-section-sources">Sources</a>
          </li>
          <li>
            <a href="#methodology-section-notices">Notices</a>
          </li>
          <li>
            <a href="#methodology-section-gaps">Gaps</a>
          </li>
          <li>
            <a href="#methodology-section-status">Status</a>
          </li>
        </ul>
      </nav>

      <section
        className="ledger-section"
        aria-labelledby="methodology-signals-heading"
        id="methodology-section-signals"
      >
        <h2 id="methodology-signals-heading">What each signal means</h2>
        <div data-testid="methodology-signals">
          <h3>CVSS: supplied severity</h3>
          <p>
            CVSS is supplied severity from record metrics, not a prediction. The displayed primary
            metric uses valid original CNA CVSS base metrics only, preferring version 4.0, then 3.1,
            then 3.0, then 2.0, choosing the highest published base among scenarios and labeling it
            the worst CNA-provided scenario. ADP-only scores stay visible as secondary metrics and
            are never silently promoted. A CVE with no valid CNA metric is unscored, not low
            severity. CVSS v2-only is legacy-scored and is not called critical. Do not treat
            different CVSS versions as calibrated alike.
          </p>
          <h3>KEV: known-exploitation evidence</h3>
          <p>
            KEV membership means the CVE is listed in the accepted CISA known-exploited catalog
            snapshot. Absence means not listed in the accepted snapshot, not proof of no
            exploitation. The date shown is the catalog addition date, not proven first exploitation
            or current attack volume.
          </p>
          <h3>EPSS: dated forecast</h3>
          <p>
            EPSS is a dated forecast of observed exploitation activity over the next 30 days, with a
            score date and model version. The percentile is a relative position among scored CVEs,
            so a 96th percentile is not a 96% exploitation probability. A missing current row is
            unknown, never zero and never silently replaced with an older score. Real zero remains
            known. Model changes can move scores without changed CVE conditions, so cross-model
            movement is not read as rising threat. EPSS is not social popularity, severity, an
            exploit count, or organization-specific risk.
          </p>
          <p className="ledger-meta">
            The three signals stay distinct. Multiplying CVSS by EPSS or mixing them with weights
            does not create a calibrated probability or risk score, so this site never computes one.
          </p>
          <h3>
            How the signals relate{" "}
            <HelpTip term="signal lanes" testId="methodology-signals-helptip">
              Each lane states what one signal is and what it is not; the lanes never merge.
            </HelpTip>
          </h3>
          <SignalDiagram />
        </div>
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-coverage-heading"
        id="methodology-section-coverage"
      >
        <h2 id="methodology-coverage-heading">What the corpus actually covers</h2>
        <p className="ledger-meta">
          Different signals cover different populations. These bars are percentages of all published
          records, not a quality score.
        </p>
        <CoverageDiagram
          published={publishedTotal ?? 0}
          cnaScored={cnaScored ?? 0}
          epssScored={epssScored ?? 0}
          kev={kevListed ?? 0}
        />
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-pipeline-heading"
        id="methodology-section-pipeline"
      >
        <h2 id="methodology-pipeline-heading">
          Ingestion-to-publication pipeline{" "}
          <HelpTip term="pipeline" testId="methodology-pipeline-helptip">
            The worker fetches; pages and the API read accepted local snapshots only.
          </HelpTip>
        </h2>
        <PipelineExplorer />
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-ordering-heading"
        id="methodology-section-ordering"
      >
        <h2 id="methodology-ordering-heading">
          Exact ordering rules (ranking policy {RANKING_POLICY_VERSION})
        </h2>
        <p className="ledger-meta">
          All views first join against current PUBLISHED CVEs. Missing optional values are
          explicitly unknown. Lists sort raw, unrounded source values, never formatted display text.
          Probability and delta comparisons use exact source-decimal arithmetic. Rounding is for
          display only.
        </p>
        <div data-testid="methodology-ordering-default">
          <h3>Default priority</h3>
          <p>
            Compare these keys in order, stopping at the first difference: 1. KEV member before not
            listed in the accepted KEV snapshot. 2. Within that tier, EPSS present before unknown.
            3. Within scored records, EPSS probability descending (actual zero remains scored). 4.
            Known publication timestamp before unknown. 5. Publication timestamp descending. 6. CVE
            ID ASCII ascending.
          </p>
        </div>
        <div data-testid="methodology-ordering-known-exploited">
          <h3>Known exploited</h3>
          <p>
            KEV members only. KEV dateAdded descending, then CVE ID ASCII ascending. EPSS is not a
            sort key here.
          </p>
        </div>
        <div data-testid="methodology-ordering-highest-forecast">
          <h3>Highest forecast</h3>
          <p>
            Known EPSS only. Raw EPSS probability descending, known publication before unknown,
            publication descending, CVE ID ASCII ascending. KEV membership is not a sort key here.
            Display uses display_probability_percent = 100 * epss and display_percentile = 100 *
            percentile.
          </p>
        </div>
        <div data-testid="methodology-ordering-new-critical">
          <h3>New critical</h3>
          <p>
            Let T be the stored UTC publication cutoff. Include publication times in [T - 30d, T)
            with primary modern CVSS v2 excluded and base 9.0 or above. Order publication
            descending, then CVE ID ASCII ascending. Unknown, legacy-only, and ADP-only primary
            cases are ineligible, not low severity. No mixed-version numeric severity ordering is
            implied.
          </p>
        </div>
        <div data-testid="methodology-ordering-rising-forecast">
          <h3>Rising forecast</h3>
          <p>
            Let d be the accepted current EPSS UTC score date. Require observations on exactly d and
            d-7 calendar days with the same model version. delta_pp = 100 * (epss[d] - epss[d-7]).
            Include positive changes only. Order delta percentage-points descending, current raw
            probability descending, CVE ID ASCII ascending. Missing dates and model transitions are
            ineligible, never interpolated or zeroed. This is a forecast movement list, not social
            popularity or observed exploitation telemetry.
          </p>
        </div>
        <h3>
          Default priority as a decision flow{" "}
          <HelpTip term="default priority flow" testId="methodology-ordering-flow-helptip">
            Six keys compared top to bottom; the first difference decides.
          </HelpTip>
        </h3>
        <OrderingDiagram />
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-example-heading"
        id="methodology-section-example"
      >
        <h2 id="methodology-example-heading">Worked ordering example</h2>
        <p className="ledger-meta">
          One illustrative record, five views. The highlighted rule is the first key that explains
          its position in that view.
        </p>
        <ScoringExample />
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-sources-heading"
        id="methodology-section-sources"
      >
        <h2 id="methodology-sources-heading">Sources, dates, and versions</h2>
        <div data-testid="methodology-sources">
          <p>
            Visitor pages and the public API read accepted local snapshots only. Only the ingestion
            worker fetches upstream. Each publication pins exact source revisions and dates,
            observation times, the ranking policy version, and the eligible cohort.
          </p>
          <p>
            CVE List V5: official list, updated about every 7 minutes from the official CVE Services
            API (a stated cadence, not a maximum-latency guarantee). Target refresh here is hourly.
            Publication and update chronology come from record dates, not ingestion time.
          </p>
          <p>
            CISA KEV: full catalog snapshot with catalogVersion, dateReleased, count, and entries
            carrying cveID, dateAdded, vendorProject, product, and due dates. Target refresh here is
            hourly with conditional requests where supported.
          </p>
          <p>
            FIRST EPSS: full daily compressed CSV; columns are cve, epss, percentile, with the
            leading comment giving model_version and score_date. Target refresh here is daily after
            expected publication. Historical analysis uses dated historical files or retained daily
            observations, never the assumption that the moving current-file URL preserves past
            versions.
          </p>
          <p className="ledger-meta">
            A locally computed hash identifies bytes; it is not a publisher authenticity signature.
            Reimporting identical bytes or revisions yields the same normalized result without
            duplicates. A successful unchanged check updates health, not record-modified dates.
          </p>
        </div>
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-notices-heading"
        id="methodology-section-notices"
      >
        <h2 id="methodology-notices-heading">Reuse and attribution notices</h2>
        <p className="ledger-meta">
          Required notices, kept verbatim. A bare source link is not a substitute for reproducing
          required text.
        </p>
        <div data-testid="notice-cve">
          <h3>CVE List V5</h3>
          <p>
            The CVE usage license authorizes reproduce, prepare derivative works of, publicly
            display, publicly perform, sublicense, and distribute and requires that copies reproduce
            MITRE copyright designation and this license. It is no-charge reuse, not CC0. Public
            display and derived ordering are supported subject to these conditions. Retain the full
            applicable license and notice in distributed data and on this attribution page.
          </p>
        </div>
        <div data-testid="notice-kev">
          <h3>CISA KEV</h3>
          <p>
            The KEV database is distributed under the Creative Commons 0 1.0 License. You may use
            this data in any lawful manner. Linked third-party content keeps its own terms.
          </p>
        </div>
        <div data-testid="notice-kev-marks">
          <h3>No endorsement or marks</h3>
          <p>
            Catalog reuse grants neither use of CISA or DHS marks nor implied endorsement. Avoid
            implying upstream endorsement.
          </p>
        </div>
        <div data-testid="notice-epss">
          <h3>FIRST EPSS</h3>
          <p>
            FIRST says scores are published daily, free of charge, with no registration required.
            The services terms grant a limited, revocable license for distribution only for
            vulnerability disclosure, cybersecurity incident response, or preventative cybersecurity
            uses with notices retained.
          </p>
        </div>
        <div data-testid="notice-epss-attribution">
          <h3>EPSS attribution</h3>
          <p>
            The FAQ requests attribution in products and publications. This page is that
            attribution: forecasts come from FIRST EPSS, with score date and model version shown
            beside every value.
          </p>
        </div>
        <div data-testid="notice-first-clarification">
          <h3>FIRST terms clarification before monetization</h3>
          <p>
            A preventative dashboard appears aligned with the permitted uses; blanket permission for
            every commercial arrangement is not established. Before ads, paid access, resale, or
            other commercialization, recheck every source and clarify FIRST terms. Hosting and
            database costs are separate from data fees either way.
          </p>
        </div>
        <div data-testid="notice-not-legal-advice">
          <h3>Not legal advice</h3>
          <p>
            These are dated findings from 2026-10-24, not legal advice. Source terms can change;
            link to vendor advisories rather than copying their prose, logos, or exploit code.
          </p>
        </div>
        <div data-testid="notice-recheck">
          <h3>Recheck before launch</h3>
          <p>
            Recheck terms before launch and before adding monetization. Before release, verify
            coverage and operations, link and excerpt behavior, and changed terms.
          </p>
        </div>
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-gaps-heading"
        id="methodology-section-gaps"
      >
        <h2 id="methodology-gaps-heading">Coverage gaps</h2>
        <div data-testid="methodology-gaps">
          <p>
            Retained cohort: {publishedTotal === null ? "unknown" : publishedTotal} published
            records, {kevListed === null ? "unknown" : kevListed} KEV-listed,{" "}
            {epssScored === null ? "unknown" : epssScored} EPSS-scored,{" "}
            {unknownDates === null ? "unknown" : unknownDates} with unknown publication dates. These
            are observed counts, not completeness claims.
          </p>
          <p>
            Not promised: social popularity or most-talked-about lists (no validated source
            selected); guaranteed nickname search such as PHP2Shell (only indexed text matches,
            curated aliases would be separate editorial work); complete unpublished-reservation
            counts (the public corpus does not enumerate all reserved IDs); severity for every CVE
            (metrics, titles, languages, products, and aliases are not universally populated, so
            absence stays unknown); exact parity with any other tracker projection (snapshot
            disagreement illustrates dating, not a systematic defect).
          </p>
          <p>
            Severity filters use primary CNA metrics only; ADP-only, legacy-only, and unscored cases
            stay separate. Date and join gaps stay visible with coverage shown. Missing publication
            dates go to an explicit unknown bucket. Corrections and rejections update derived views,
            and historical totals can change. Do not estimate all unpublished reservations, annual
            counts from ID numbers, or total worldwide exploitation.
          </p>
        </div>
      </section>

      <section
        className="ledger-section"
        aria-labelledby="methodology-health-heading"
        id="methodology-section-status"
      >
        <h2 id="methodology-health-heading">Per-source data status</h2>
        <p className="ledger-meta" data-testid="methodology-health-note">
          Health comes from the sync_runs table: the latest run per source for check time, the
          latest succeeded run for accepted data, and any failure message. State is text plus
          symbol, never color alone: = is current, ~ is stale, ! is source failed, ? is missing. A
          missing feed keeps serving last-known-good data with a visible per-source warning; one
          failed feed never freezes the others.
        </p>
        {loadError !== null ? (
          <p className="ledger-meta" data-testid="methodology-health-error">
            The retained snapshot could not be read: {loadError}. Nothing is interpolated;
            per-source states below are missing.
          </p>
        ) : null}
        <div data-testid="methodology-health">
          {lines.map((line) => (
            <div
              key={line.key}
              className="ledger-evidence"
              data-testid={`methodology-health-${line.key}`}
            >
              <span className="ledger-evidence-symbol" aria-hidden="true">
                {line.symbol}
              </span>
              <span className="ledger-evidence-state">
                {line.name}: {line.label}
              </span>
              <span data-testid={`methodology-health-${line.key}-detail`}>
                {line.detail}
                {line.warning !== null ? ` ${line.warning}` : ""}
              </span>
            </div>
          ))}
        </div>
        <p className="ledger-meta" data-testid="methodology-freshness-targets">
          Targets are ours, not upstream SLAs: CVE hourly, KEV hourly, EPSS daily after expected
          publication. CVE and KEV flag stale when the last successful check is more than 3 hours
          old. EPSS flags stale when the accepted score date is older than 2 UTC calendar days. An
          old vulnerability is never flagged merely because its record has not changed.
        </p>
      </section>

      <section className="ledger-section" aria-labelledby="methodology-checklist-heading">
        <h2 id="methodology-checklist-heading">Launch checklist</h2>
        <div data-testid="methodology-checklist">
          <p>
            Before release, and again before any monetization, recheck each item with its check date
            recorded: CVE Terms of Use (copyright designation and license reproduced); CISA KEV CC0
            1.0 terms (marks and third-party links excluded); FIRST EPSS data access, FAQ
            attribution, and services terms (preventative-use scope and retained notices); every
            notice on this page still present verbatim; failed-feed behavior verified
            (last-known-good served with a visible stale warning); coverage and operations measured
            rather than claimed.
          </p>
        </div>
      </section>
    </main>
  );
}
