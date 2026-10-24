// Priority list views (plan todo 20). Server component reading the accepted
// local snapshots through the deterministic priority services in
// `src/lib/priority` — the same code the versioned API reads. Four named
// modes only: known-exploited, highest-forecast, new-critical,
// rising-forecast. No "Popular" tab, no blended or composite score anywhere:
// each mode states its exact ordering inputs beside the list it explains.
// Unknown and stale values are labeled in place, never zeroed or hidden.

import path from "node:path";

import { Masthead } from "@/components/ledger/Masthead";
import {
  PRIORITY_MODES,
  PRIORITY_MODE_LABELS,
  PriorityEvidence,
  PriorityList,
  PriorityModeNav,
  PriorityOrdering,
  type PriorityMode,
  type PriorityRowData,
} from "@/components/priority/PriorityView";
import { openDatabase, type CveDatabase } from "@/lib/db";
import {
  getAcceptedEpssDate,
  getDefaultPriority,
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
  coverageFor,
  loadFullRecords,
  RANKING_POLICY_VERSION,
  type FullRecord,
} from "@/app/api/v1/_lib/shared";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Priority lists - CVE Change Radar",
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
      record.epssText !== null ? (displayProbabilityPercent(record.epssText) ?? record.epssText) : null,
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
  rowsByMode: Record<PriorityMode, PriorityRowData[]>;
  coverageByMode: Record<PriorityMode, { eligibleCohort: number; returned: number }>;
  corpusUnscored: number;
  corpusUnknownEpss: number;
  corpusUnknownDate: number;
}

function loadSnapshot(db: CveDatabase, nowIso: string): PrioritySnapshot {
  const scoreDate = getAcceptedEpssDate(db);
  const scoreModel =
    scoreDate === null
      ? null
      : (() => {
          const row = db.handle
            .prepare("SELECT model_version FROM epss_daily WHERE score_date = ? ORDER BY model_version DESC LIMIT 1")
            .get(scoreDate) as { model_version: string } | undefined;
          return row?.model_version ?? null;
        })();
  const provenance = buildProvenance(db, nowIso);
  const publishedRow = db.handle
    .prepare("SELECT COUNT(*) AS n FROM cve_records WHERE state = ?")
    .get("PUBLISHED") as { n: number };

  const knownExploited = getKnownExploited(db);
  const highestForecast = getHighestForecast(db);
  const newCritical = getNewCritical(db, nowIso);
  const rising = getRisingForecast(db);
  const corpus = getDefaultPriority(db);
  const corpusCoverage = coverageFor(corpus, corpus.length);

  const previousDate = scoreDate === null ? null : minus7Days(scoreDate);
  const deltaById = new Map<string, { deltaPp: string; previousDate: string }>();
  if (previousDate !== null) {
    for (const row of rising) {
      deltaById.set(row.item.id, { deltaPp: row.deltaPp, previousDate });
    }
  }

  const byModeItems: Record<PriorityMode, PriorityItem[]> = {
    "known-exploited": knownExploited,
    "highest-forecast": highestForecast,
    "new-critical": newCritical,
    "rising-forecast": rising.map((row) => row.item),
  };
  const ids = [...new Set((Object.values(byModeItems) as PriorityItem[][]).flat().map((item) => item.id))];
  const records = new Map(loadFullRecords(db, ids).map((record) => [record.cveId, record]));

  const rowsByMode = {
    "known-exploited": knownExploited
      .map((item) => toRow(item, records, scoreDate, deltaById))
      .filter((row): row is PriorityRowData => row !== null),
    "highest-forecast": highestForecast
      .map((item) => toRow(item, records, scoreDate, deltaById))
      .filter((row): row is PriorityRowData => row !== null),
    "new-critical": newCritical
      .map((item) => toRow(item, records, scoreDate, deltaById))
      .filter((row): row is PriorityRowData => row !== null),
    "rising-forecast": rising
      .map((row) => toRow(row.item, records, scoreDate, deltaById))
      .filter((row): row is PriorityRowData => row !== null),
  } satisfies Record<PriorityMode, PriorityRowData[]>;

  const coverageByMode = {
    "known-exploited": { eligibleCohort: knownExploited.length, returned: rowsByMode["known-exploited"].length },
    "highest-forecast": { eligibleCohort: highestForecast.length, returned: rowsByMode["highest-forecast"].length },
    "new-critical": { eligibleCohort: newCritical.length, returned: rowsByMode["new-critical"].length },
    "rising-forecast": { eligibleCohort: rising.length, returned: rowsByMode["rising-forecast"].length },
  } satisfies Record<PriorityMode, { eligibleCohort: number; returned: number }>;

  return {
    scoreDate,
    scoreModel,
    epssStale: provenance.sources.epss.stale,
    publishedCount: publishedRow.n,
    cutoffT: nowIso,
    rowsByMode,
    coverageByMode,
    corpusUnscored: corpusCoverage.unscored,
    corpusUnknownEpss: corpusCoverage.unknownEpss,
    corpusUnknownDate: corpusCoverage.unknownDate,
  };
}

function orderingBody(mode: PriorityMode, snapshot: PrioritySnapshot): string {
  const score =
    snapshot.scoreDate !== null
      ? `EPSS score date ${snapshot.scoreDate}${snapshot.scoreModel !== null ? `, model ${snapshot.scoreModel}` : ""}.`
      : "No accepted EPSS score date in this snapshot.";
  const coverage = snapshot.coverageByMode[mode];
  const denominator = `Coverage: ${coverage.eligibleCohort} listed of ${snapshot.publishedCount} published records in the retained cohort. Corpus gaps: ${snapshot.corpusUnscored} unscored, ${snapshot.corpusUnknownEpss} unknown EPSS, ${snapshot.corpusUnknownDate} unknown publication date.`;
  const extras: Record<PriorityMode, string> = {
    "known-exploited":
      "Catalog dates mark catalog addition, not proven first exploitation or current attack volume. EPSS is not a sort key here.",
    "highest-forecast":
      "Display shows rounded percentages; ordering uses raw source decimals. KEV membership is not a sort key here. Records with unknown EPSS are ineligible for this view, never zero.",
    "new-critical":
      `Window cutoff T is ${snapshot.cutoffT}. Unknown, legacy-only (v2), and ADP-only primary cases are ineligible, not low severity. No mixed-version numeric severity ordering is implied.`,
    "rising-forecast":
      "Missing dates and model transitions are ineligible, never interpolated or zeroed. This is a forecast movement list, not social popularity or observed exploitation telemetry.",
  };
  return `${score} ${denominator} ${extras[mode]}`;
}

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
    const db = openDatabase({ dataDir: resolveDataDir() });
    try {
      snapshot = loadSnapshot(db, new Date().toISOString());
    } finally {
      db.close();
    }
  } catch (error) {
    loadError = error instanceof Error ? error.message : String(error);
  }

  return (
    <main className="ledger-page" data-testid="priority-root">
      <Masthead current="Priority" testId="priority-masthead" />
      <h1>Priority lists</h1>
      <p className="ledger-meta" data-testid="priority-intro">
        Four named views over the retained PUBLISHED cohort. Signals stay distinct: KEV is confirmed-exploitation
        evidence, EPSS is a dated forecast, CVSS is supplied severity. No composite score is computed and no
        popularity signal exists. Ranking policy {RANKING_POLICY_VERSION}.
      </p>

      {loadError !== null || snapshot === null ? (
        <section className="ledger-section" data-testid="priority-load-error">
          <h2>Priority data unavailable</h2>
          <p className="ledger-meta">
            The retained snapshot could not be read: {loadError ?? "unknown error"}. Nothing is interpolated;
            try again once ingestion has published a snapshot.
          </p>
        </section>
      ) : (
        <>
          <PriorityModeNav current={mode} />
          {PRIORITY_MODES.filter((candidate) => candidate === mode).map((active) => (
            <section
              key={active}
              className="ledger-section"
              aria-labelledby="priority-mode-heading"
              data-testid={`priority-section-${active}`}
            >
              <h2 id="priority-mode-heading" data-testid="priority-mode-heading">
                {PRIORITY_MODE_LABELS[active]}
              </h2>
              <PriorityOrdering mode={active} body={orderingBody(active, snapshot)} />
              <PriorityEvidence
                stale={snapshot.epssStale}
                testId={`priority-evidence-${active}`}
                detail={
                  snapshot.epssStale
                    ? `EPSS score date ${snapshot.scoreDate ?? "unknown"} is older than 2 UTC calendar days. Dated values are retained with this label; they are never relabeled as current-day forecasts.`
                    : snapshot.scoreDate !== null
                      ? `CVE List V5 and KEV per retained manifest, observed at request time. EPSS model ${snapshot.scoreModel ?? "unknown"} dated ${snapshot.scoreDate}. KEV catalog dates mark catalog addition.`
                      : "No accepted EPSS score date in this snapshot. EPSS values render as unavailable, never zero."
                }
              />
              <p className="ledger-meta" data-testid={`priority-coverage-${active}`}>
                Coverage denominator: {snapshot.coverageByMode[active].eligibleCohort} eligible of{" "}
                {snapshot.publishedCount} published records.
              </p>
              <p className="ledger-meta" data-testid={`priority-methodology-${active}`}>
                <a href="/methodology">Methodology, sources, and reuse notices</a>
              </p>
              <PriorityList rows={snapshot.rowsByMode[active]} mode={active} />
            </section>
          ))}
        </>
      )}
    </main>
  );
}
