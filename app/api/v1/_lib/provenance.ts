import { singleText } from "../../../../src/lib/aggregates";
import type { CveDatabase } from "../../../../src/lib/db";
import { getAcceptedEpssDate } from "../../../../src/lib/priority";
import { DAY_RE } from "./params";

/** Ranking policy version pinned into every provenance envelope. */
export const RANKING_POLICY_VERSION = "ranking-v1";

export interface SourceProvenance {
  revision?: string | null;
  catalogVersion?: string | null;
  scoreDate?: string | null;
  modelVersion?: string | null;
  lastCheckedAt: string | null;
  lastAcceptedAt: string | null;
  stale: boolean;
  error: string | null;
}

export interface Provenance {
  rankingPolicyVersion: string;
  generatedAt: string;
  sources: {
    cve: SourceProvenance;
    kev: SourceProvenance;
    epss: SourceProvenance;
    /** CISA Vulnrichment SSVC enrichment (daily); absent until first success. */
    ssvc: SourceProvenance;
  };
}

interface SyncRun {
  started_at: string;
  finished_at: string | null;
  status: string;
  revision: string | null;
  error: string | null;
}

function latestRun(db: CveDatabase, source: string): SyncRun | undefined {
  return db.handle
    .prepare(
      "SELECT started_at, finished_at, status, revision, error FROM sync_runs WHERE source = ? ORDER BY id DESC LIMIT 1",
    )
    .get(source) as SyncRun | undefined;
}

function latestSucceeded(db: CveDatabase, source: string): SyncRun | undefined {
  return db.handle
    .prepare(
      "SELECT started_at, finished_at, status, revision, error FROM sync_runs WHERE source = ? AND status = ? ORDER BY id DESC LIMIT 1",
    )
    .get(source, "succeeded") as SyncRun | undefined;
}

function parseEpssRevision(revision: string | null): {
  scoreDate: string | null;
  modelVersion: string | null;
} {
  if (revision === null) return { scoreDate: null, modelVersion: null };
  const at = revision.indexOf("@");
  if (at <= 0) return { scoreDate: null, modelVersion: null };
  const scoreDate = revision.slice(0, at);
  const modelVersion = revision.slice(at + 1);
  if (!DAY_RE.test(scoreDate) || modelVersion === "")
    return { scoreDate: null, modelVersion: null };
  return { scoreDate, modelVersion };
}

function staleAfterHours(lastAcceptedAt: string | null, nowMs: number, hours: number): boolean {
  if (lastAcceptedAt === null) return false;
  const acceptedMs = Date.parse(lastAcceptedAt);
  if (!Number.isFinite(acceptedMs)) return false;
  return nowMs - acceptedMs > hours * 3_600_000;
}

function epssStale(scoreDate: string | null, nowIso: string): boolean {
  if (scoreDate === null || !DAY_RE.test(scoreDate)) return false;
  const today = nowIso.slice(0, 10);
  if (!DAY_RE.test(today)) return false;
  const ageDays =
    (Date.parse(`${today}T00:00:00.000Z`) - Date.parse(`${scoreDate}T00:00:00.000Z`)) / 86_400_000;
  return ageDays > 2;
}

function sourceError(run: SyncRun | undefined): string | null {
  if (run === undefined || run.status !== "failed") return null;
  return typeof run.error === "string" && run.error !== "" ? run.error : "refresh failed";
}

export function buildProvenance(db: CveDatabase | null, nowIso: string): Provenance {
  const nowMs = Date.parse(nowIso);
  const safeNowMs = Number.isFinite(nowMs) ? nowMs : Date.now();
  const fallback = {
    lastCheckedAt: null as string | null,
    lastAcceptedAt: null as string | null,
    stale: false,
    error: null as string | null,
  };
  if (db === null) {
    return {
      rankingPolicyVersion: RANKING_POLICY_VERSION,
      generatedAt: nowIso,
      sources: {
        cve: { revision: null, ...fallback },
        kev: { catalogVersion: null, ...fallback },
        epss: { scoreDate: null, modelVersion: null, ...fallback },
        ssvc: { revision: null, ...fallback },
      },
    };
  }
  const cveRun = latestRun(db, "cve");
  const cveOk = latestSucceeded(db, "cve");
  const kevRun = latestRun(db, "kev");
  const kevOk = latestSucceeded(db, "kev");
  const epssRun = latestRun(db, "epss");
  const epssOk = latestSucceeded(db, "epss");
  const ssvcRun = latestRun(db, "ssvc");
  const ssvcOk = latestSucceeded(db, "ssvc");

  const cveRevision =
    cveOk?.revision ?? singleText(db, "SELECT MAX(source_revision) FROM cve_records") ?? null;
  const kevCatalog =
    kevOk?.revision ?? singleText(db, "SELECT MAX(catalog_date) FROM kev_entries") ?? null;
  const parsed = parseEpssRevision(epssOk?.revision ?? null);
  const acceptedDate = parsed.scoreDate ?? getAcceptedEpssDate(db);
  const acceptedModel =
    parsed.modelVersion ??
    (acceptedDate === null
      ? null
      : (singleText(
          db,
          "SELECT model_version FROM epss_daily WHERE score_date = ? ORDER BY model_version DESC LIMIT 1",
          [acceptedDate],
        ) ?? null));
  const epssScoreDate = parsed.scoreDate ?? acceptedDate;
  const epssModel = parsed.modelVersion ?? (parsed.scoreDate !== null ? null : acceptedModel);

  const cveAccepted = cveOk?.finished_at ?? cveOk?.started_at ?? null;
  const kevAccepted = kevOk?.finished_at ?? kevOk?.started_at ?? null;
  const epssAccepted = epssOk?.finished_at ?? epssOk?.started_at ?? null;
  const ssvcAccepted = ssvcOk?.finished_at ?? ssvcOk?.started_at ?? null;
  return {
    rankingPolicyVersion: RANKING_POLICY_VERSION,
    generatedAt: nowIso,
    sources: {
      cve: {
        revision: cveRevision,
        lastCheckedAt: cveRun?.finished_at ?? cveRun?.started_at ?? null,
        lastAcceptedAt: cveAccepted,
        stale: staleAfterHours(cveAccepted, safeNowMs, 3),
        error: sourceError(cveRun),
      },
      kev: {
        catalogVersion: kevCatalog,
        lastCheckedAt: kevRun?.finished_at ?? kevRun?.started_at ?? null,
        lastAcceptedAt: kevAccepted,
        stale: staleAfterHours(kevAccepted, safeNowMs, 3),
        error: sourceError(kevRun),
      },
      epss: {
        scoreDate: epssScoreDate,
        modelVersion: epssModel,
        lastCheckedAt: epssRun?.finished_at ?? epssRun?.started_at ?? null,
        lastAcceptedAt: epssAccepted,
        stale: epssStale(epssScoreDate, nowIso),
        error: sourceError(epssRun),
      },
      ssvc: {
        // Enrichment is daily, so staleness is measured against the last
        // successful cycle rather than a score date.
        revision: ssvcOk?.revision ?? null,
        lastCheckedAt: ssvcRun?.finished_at ?? ssvcRun?.started_at ?? null,
        lastAcceptedAt: ssvcAccepted,
        stale: staleAfterHours(ssvcAccepted, safeNowMs, 48),
        error: sourceError(ssvcRun),
      },
    },
  };
}
