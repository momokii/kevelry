// Secondary-CVSS projection for the read path (v3 E1).
//
// The primary metric is an editorial selection (ranking.ts, `selectPrimaryCvss`);
// every other preserved metric is *secondary context*. This module owns the
// grouping, validity filter, ordering, cap, and wording for that secondary
// block so no route or component re-derives it.
//
// Contract:
// - Pure: no IO, no mutation of the input, deterministic for the same input.
// - Never throws on hostile data: malformed metrics are ignored, and the
//   function itself is wrapped so a caller never sees an exception.
// - Secondary metrics are context only. They are never promoted to primary and
//   never used for ranking, ordering, eligibility, filtering, or severity bands.
// - Ordering: ADP before CNA, then version preference 4.0 > 3.1 > 3.0 > 2.0,
//   then exact base-score descending, then stored source order, then provider
//   and vector ASCII (a stable tie-break for identical rows).
// - Bounded to MAX_SECONDARY_METRICS entries.

import {
  asciiCompare,
  compareDecimalStrings,
  cvssVersionRank,
  isCvssVersion,
  isValidCvssScore,
  type CvssVersion,
} from "./ranking";

export const MAX_SECONDARY_METRICS = 4;

export const SECONDARY_LABEL = "secondary (context only)" as const;

export interface CvssMetricView {
  origin: "CNA" | "ADP";
  provider: string | null;
  version: string;
  baseScore: string;
  vector: string;
  label: typeof SECONDARY_LABEL;
}

export interface CvssSecondary {
  status: "present" | "none";
  coverageNote: string;
  metrics: CvssMetricView[];
}

const PRESENT_NOTE =
  "Secondary (context only): metrics other than the selected primary. They are not used for ranking or eligibility.";
const NONE_NOTE =
  "No secondary (ADP or non-selected CNA) metric is published. Any secondary would be context only and is not used for ranking or eligibility.";

interface Candidate {
  origin: "CNA" | "ADP";
  provider: string | null;
  version: CvssVersion;
  baseScore: string;
  vector: string;
  sourceOrder: number;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value === "object" && value !== null) return value as Record<string, unknown>;
  return {};
}

function providerOf(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

function toCandidate(metric: unknown, index: number): Candidate | null {
  const row = asRecord(metric);
  const origin = row.origin;
  if (origin !== "CNA" && origin !== "ADP") return null;
  if (!isCvssVersion(row.version)) return null;
  if (!isValidCvssScore(row.baseScore)) return null;
  const order =
    typeof row.sourceOrder === "number" && Number.isFinite(row.sourceOrder)
      ? row.sourceOrder
      : index;
  return {
    origin,
    provider: providerOf(row.provider),
    version: row.version,
    baseScore: row.baseScore,
    vector: typeof row.vector === "string" ? row.vector : "",
    sourceOrder: order,
  };
}

function primaryKey(primary: unknown): {
  origin: string;
  version: string;
  baseScore: string;
  vector: string;
} | null {
  const row = asRecord(primary);
  if (typeof row.origin !== "string") return null;
  if (typeof row.version !== "string") return null;
  if (typeof row.baseScore !== "string") return null;
  return {
    origin: row.origin,
    version: row.version,
    baseScore: row.baseScore,
    vector: typeof row.vector === "string" ? row.vector : "",
  };
}

/** True when the stored metric is the same source metric the primary selected. */
function equalsPrimary(
  candidate: Candidate,
  primary: NonNullable<ReturnType<typeof primaryKey>>,
): boolean {
  if (candidate.origin !== primary.origin) return false;
  if (candidate.version !== primary.version) return false;
  // Exact decimal equality: "9.80" and "9.8" are the same published score.
  if (compareDecimalStrings(candidate.baseScore, primary.baseScore) !== 0) return false;
  return candidate.vector === primary.vector;
}

function orderCandidates(a: Candidate, b: Candidate): number {
  if (a.origin !== b.origin) return a.origin === "ADP" ? -1 : 1;
  const version = cvssVersionRank(a.version) - cvssVersionRank(b.version);
  if (version !== 0) return version;
  const score = compareDecimalStrings(b.baseScore, a.baseScore);
  if (score !== null && score !== 0) return score;
  if (a.sourceOrder !== b.sourceOrder) return a.sourceOrder - b.sourceOrder;
  const provider = asciiCompare(a.provider ?? "", b.provider ?? "");
  if (provider !== 0) return provider;
  return asciiCompare(a.vector, b.vector);
}

/**
 * Project the stored metric rows into the bounded, labeled secondary block.
 *
 * `primary` is the object returned by `selectPrimaryCvss` (or null). Only the
 * one metric it selected is excluded; all other valid CNA and ADP metrics are
 * preserved as context.
 */
export function projectSecondaryCvss(metrics: unknown, primary: unknown): CvssSecondary {
  try {
    const rows = Array.isArray(metrics) ? metrics : [];
    const selected = primaryKey(primary);
    const candidates: Candidate[] = [];
    for (let index = 0; index < rows.length; index += 1) {
      const candidate = toCandidate(rows[index], index);
      if (candidate === null) continue;
      if (selected !== null && equalsPrimary(candidate, selected)) continue;
      candidates.push(candidate);
    }
    candidates.sort(orderCandidates);
    const bounded = candidates.slice(0, MAX_SECONDARY_METRICS);
    if (bounded.length === 0) {
      return { status: "none", coverageNote: NONE_NOTE, metrics: [] };
    }
    return {
      status: "present",
      coverageNote: PRESENT_NOTE,
      metrics: bounded.map((candidate) => ({
        origin: candidate.origin,
        provider: candidate.provider,
        version: candidate.version,
        baseScore: candidate.baseScore,
        vector: candidate.vector,
        label: SECONDARY_LABEL,
      })),
    };
  } catch {
    // Hostile rows degrade to "none"; the read path never fails on CVSS data.
    return { status: "none", coverageNote: NONE_NOTE, metrics: [] };
  }
}
