// Priority list views (plan todo 20). Server component reading the accepted
// local snapshots through the deterministic priority services in
// `src/lib/priority` — the same code the versioned API reads. Four named
// modes only: known-exploited, highest-forecast, new-critical,
// rising-forecast. No "Popular" tab, no blended or composite score anywhere:
// each mode states its exact ordering inputs beside the list it explains.
// Unknown and stale values are labeled in place, never zeroed or hidden.

import path from "node:path";

import { TimeText } from "@/components/ledger/TimeText";
import {
  PRIORITY_MODE_LABELS,
  PriorityEvidence,
  PriorityList,
  PriorityModeNav,
  PriorityOrdering,
  PrioritySummary,
  type PriorityMode,
  type PriorityRowData,
} from "@/components/priority/PriorityView";
import { openReadDatabase, type CveDatabase } from "@/lib/db";
import { PageHeader } from "@/components/shell/PageHeader";
import { Panel } from "@/components/shell/Panel";
import {
  getAcceptedEpssDate,
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
  type PriorityItem,
} from "@/lib/priority";
import { displayProbabilityPercent } from "@/lib/ranking";
import { excerptDescription, officialCveLink } from "@/lib/search";
import {
  buildProvenance,
  loadFullRecords,
  RANKING_POLICY_VERSION,
  type FullRecord,
  unfilteredCohortCoverage,
} from "@/app/api/v1/_lib/shared";

export const revalidate = 60;

// Display cap for every priority list on this page. The ranking services can
// materialize the full ~395k-row corpus when called without a limit (which
// aborted the Next server via better-sqlite3), so every getter below receives
// this bound and the SQL-backed getters only hydrate the top rows. Ordering
// semantics are untouched: each bounded call returns the same prefix as
// full-order-then-slice. Overridable via PRIORITY_PAGE_LIMIT for QA; invalid
// values fall back to the default.
export const PRIORITY_PAGE_LIMIT = 100;

export function resolvePriorityPageLimit(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.PRIORITY_PAGE_LIMIT;
  if (raw === undefined || raw.trim() === "") return PRIORITY_PAGE_LIMIT;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > 1000) return PRIORITY_PAGE_LIMIT;
  return value;
}

export const metadata = {
  title: "Priority — Kevelry",
  description:
    "Four named CVE priority views with exact ordering rules, score dates, and coverage. No composite score.",
};

function isPriorityMode(value: unknown): value is PriorityMode {
  return (
    value === "known-exploited" ||
    value === "highest-forecast" ||
    value === "new-critical" ||
    value === "rising-forecast"
  );
}

function resolveDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") return raw;
  return path.join(process.cwd(), "data");
}

function minus7Days(day: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return null;
  const ms = Date.parse(`${day}T00:00:00.000Z`);
  if (!Number.isFinite(ms)) return null;
  if (new Date(ms).toISOString().slice(0, 10) !== day) return null;
  return new Date(ms - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

function toRow(
  item: PriorityItem,
  records: Map<string, FullRecord>,
  scoreDate: string | null,
  deltaById: Map<string, { deltaPp: string; previousDate: string }>,
): PriorityRowData | null {
  const record = records.get(item.id);
  if (record === undefined) return null;
  const title =
    typeof record.title === "string" && record.title.trim() !== "" ? record.title : record.cveId;
  const shaped = excerptDescription(record.description, record.descriptionLang);
  const excerpt =
    shaped.excerpt === "Description not supplied" && shaped.langLabel === "unknown"
      ? null
      : shaped.excerpt;
  const primary = record.primary;
  const delta = deltaById.get(item.id);
  return {
    id: item.id,
    title,
    excerpt,
    excerptTruncated: shaped.truncated,
    publishedAt: record.publishedAt,
    kevListed: record.kevDateAdded !== null,
    kevDateAdded: record.kevDateAdded,
    epssKnown: record.epssText !== null,
    epssPercent:
      record.epssText !== null
        ? (displayProbabilityPercent(record.epssText) ?? record.epssText)
        : null,
    epssModel: record.epssModel,
    epssDate: scoreDate,
    primaryKnown: primary !== null && primary.version !== "2.0",
    primaryLegacy: primary !== null && primary.version === "2.0",
    primaryAdpOnly: primary === null && record.hasAdp,
    primaryVersion: primary?.version ?? null,
    primaryScore: primary?.baseScore ?? null,
    deltaPp: delta?.deltaPp ?? null,
    deltaPreviousDate: delta?.previousDate ?? null,
    officialUrl: officialCveLink(item.id),
  };
}

interface PrioritySnapshot {
  scoreDate: string | null;
  scoreModel: string | null;
  epssStale: boolean;
  publishedCount: number;
  cutoffT: string;
  displayLimit: number;
  mode: PriorityMode;
  rows: PriorityRowData[];
  eligibleCohort: number;
  returned: number;
  corpusUnscored: number;
  corpusUnknownEpss: number;
  corpusUnknownDate: number;
}

export function loadSnapshot(
  db: CveDatabase,
  nowIso: string,
  mode: PriorityMode,
  limit: number = resolvePriorityPageLimit(),
): PrioritySnapshot {
  const scoreDate = getAcceptedEpssDate(db);
  const scoreModel =
    scoreDate === null
      ? null
      : (() => {
          const row = db.handle
            .prepare(
              "SELECT model_version FROM epss_daily WHERE score_date = ? ORDER BY model_version DESC LIMIT 1",
            )
            .get(scoreDate) as { model_version: string } | undefined;
          return row?.model_version ?? null;
        })();
  const provenance = buildProvenance(db, nowIso);
  const publishedRow = db.handle
    .prepare("SELECT COUNT(*) AS n FROM cve_records WHERE state = ?")
    .get("PUBLISHED") as { n: number };

  // Only the requested mode is computed: every getter is display-limited
  // (unbounded calls materialize one object per corpus row per list and abort
  // the server), and modes the response never renders are never loaded.
  // Bounded calls return the full-order-then-slice prefix, so ranking is
  // untouched. The default-priority corpus is not materialized at all: its
  // only page use was gap counts, which come from indexed COUNT queries.
  const rising = mode === "rising-forecast" ? getRisingForecast(db, undefined, limit) : [];
  const items: PriorityItem[] =
    mode === "known-exploited"
      ? getKnownExploited(db, limit)
      : mode === "highest-forecast"
        ? getHighestForecast(db, limit)
        : mode === "new-critical"
          ? getNewCritical(db, nowIso, limit)
          : rising.map((row) => row.item);
  const corpusCoverage = unfilteredCohortCoverage(db, Math.min(limit, items.length));

  const previousDate = scoreDate === null ? null : minus7Days(scoreDate);
  const deltaById = new Map<string, { deltaPp: string; previousDate: string }>();
  if (previousDate !== null) {
    for (const row of rising) {
      deltaById.set(row.item.id, { deltaPp: row.deltaPp, previousDate });
    }
  }

  const ids = [...new Set(items.map((item) => item.id))];
  const records = new Map(loadFullRecords(db, ids).map((record) => [record.cveId, record]));

  const rows = items
    .map((item) => toRow(item, records, scoreDate, deltaById))
    .filter((row): row is PriorityRowData => row !== null);

  return {
    scoreDate,
    scoreModel,
    epssStale: provenance.sources.epss.stale,
    publishedCount: publishedRow.n,
    cutoffT: nowIso,
    displayLimit: limit,
    mode,
    rows,
    eligibleCohort: items.length,
    returned: rows.length,
    corpusUnscored: corpusCoverage.unscored,
    corpusUnknownEpss: corpusCoverage.unknownEpss,
    corpusUnknownDate: corpusCoverage.unknownDate,
  };
}

function orderingCoverage(snapshot: PrioritySnapshot): string {
  return `Coverage: ${snapshot.eligibleCohort} listed of ${snapshot.publishedCount} published records in the retained cohort. Corpus gaps: ${snapshot.corpusUnscored} unscored, ${snapshot.corpusUnknownEpss} unknown EPSS, ${snapshot.corpusUnknownDate} unknown publication date.`;
}

const ORDERING_EXTRAS: Record<PriorityMode, string> = {
  "known-exploited":
    "Catalog dates mark catalog addition, not proven first exploitation or current attack volume. EPSS is not a sort key here.",
  "highest-forecast":
    "Display shows rounded percentages; ordering uses raw source decimals. KEV membership is not a sort key here. Records with unknown EPSS are ineligible for this view, never zero.",
  "new-critical":
    "Unknown, legacy-only (v2), and ADP-only primary cases are ineligible, not low severity. No mixed-version numeric severity ordering is implied.",
  "rising-forecast":
    "Missing dates and model transitions are ineligible, never interpolated or zeroed. This is a forecast movement list, not social popularity or observed exploitation telemetry.",
};

export default async function PriorityPage({
  searchParams,
}: {
  searchParams: Promise<{ view?: string }>;
}) {
  const params = await searchParams;
  const requested = Array.isArray(params.view) ? params.view[0] : params.view;
  const mode: PriorityMode = isPriorityMode(requested) ? requested : "known-exploited";

  let snapshot: PrioritySnapshot | null = null;
  let loadError: string | null = null;
  try {
    const db = openReadDatabase(resolveDataDir());
    snapshot = loadSnapshot(db, new Date().toISOString(), mode);
  } catch (error) {
    loadError = error instanceof Error ? error.message : String(error);
  }

  return (
    <main className="page" data-testid="priority-root" id="main-content">
      <PageHeader
        eyebrow={
          <>
            <span>Priority</span>
            <span className="dot" aria-hidden="true" />
            <span>Policy {RANKING_POLICY_VERSION}</span>
            <span className="dot" aria-hidden="true" />
            <span>four named views</span>
          </>
        }
        title="What deserves attention now?"
        lede={
          <span data-testid="priority-intro">
            KEV is confirmed-exploitation evidence, EPSS is a dated forecast, CVSS is supplied
            severity. Signals stay distinct; no composite score and no popularity signal exist.
          </span>
        }
        actions={
          <a className="btn btn-sm" href="/methodology#methodology-section-ordering">
            Ordering rules
          </a>
        }
      />

      {loadError !== null || snapshot === null ? (
        <div className="notice" data-testid="priority-load-error">
          <span>
            <strong>Priority data unavailable.</strong> The retained snapshot could not be read:{" "}
            {loadError ?? "unknown error"}. Nothing is interpolated; try again once ingestion has
            published a snapshot.
          </span>
        </div>
      ) : (
        <>
          <PriorityModeNav current={mode} />
          <div className="priority-layout" data-testid={`priority-section-${mode}`}>
            <div className="priority-main">
              <div className="priority-list-head">
                <h2 id="priority-mode-heading" data-testid="priority-mode-heading">
                  {PRIORITY_MODE_LABELS[mode]}
                </h2>
                <PrioritySummary
                  mode={mode}
                  scoreDate={snapshot.scoreDate}
                  scoreModel={snapshot.scoreModel}
                  displayed={Math.min(snapshot.displayLimit, snapshot.returned)}
                  eligible={snapshot.eligibleCohort}
                  publishedTotal={snapshot.publishedCount}
                  stale={snapshot.epssStale}
                />
              </div>
              <PriorityList rows={snapshot.rows} mode={mode} />
              <p className="chart-note" data-testid={`priority-coverage-${mode}`}>
                Coverage denominator: {snapshot.eligibleCohort} eligible of{" "}
                {snapshot.publishedCount} published records.
              </p>
              <p className="chart-note" data-testid={`priority-display-limit-${mode}`}>
                Showing top {snapshot.displayLimit} of the cohort for this view. Ordering and
                eligibility are unchanged; only the display is truncated.
              </p>
              <p className="chart-note" data-testid={`priority-methodology-${mode}`}>
                <a href="/methodology">Methodology, sources, and reuse notices</a>
              </p>
            </div>

            <aside className="priority-rail">
              <Panel
                title="How this list is ordered"
                sub="First key wins; ties break deterministically."
              >
                <PriorityOrdering
                  mode={mode}
                  coverage={orderingCoverage(snapshot)}
                  extra={ORDERING_EXTRAS[mode]}
                  scoreDate={snapshot.scoreDate}
                  scoreModel={snapshot.scoreModel}
                  cutoffT={mode === "new-critical" ? snapshot.cutoffT : null}
                />
              </Panel>
              <Panel title="Snapshot evidence">
                <PriorityEvidence
                  stale={snapshot.epssStale}
                  testId={`priority-evidence-${mode}`}
                  detail={
                    snapshot.epssStale ? (
                      <>
                        EPSS score date{" "}
                        <TimeText
                          value={snapshot.scoreDate}
                          testId="priority-evidence-score-date"
                        />{" "}
                        is older than 2 UTC calendar days. Dated values are retained with this
                        label; they are never relabeled as current-day forecasts.
                      </>
                    ) : snapshot.scoreDate !== null ? (
                      <>
                        EPSS model {snapshot.scoreModel ?? "unknown"} dated{" "}
                        <TimeText
                          value={snapshot.scoreDate}
                          testId="priority-evidence-score-date"
                        />
                        . KEV catalog dates mark catalog addition, not first exploitation.
                      </>
                    ) : (
                      "No accepted EPSS score date in this snapshot. EPSS values render as unavailable, never zero."
                    )
                  }
                />
              </Panel>
            </aside>
          </div>
        </>
      )}
    </main>
  );
}
