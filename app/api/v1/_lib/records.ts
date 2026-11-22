import type { PriorityItem } from "../../../../src/lib/priority";
import {
  exploitReferencesOf,
  kevRansomwareUseOf,
  legacyRansomwareKnown,
  type FullRecord,
  type KevRansomwareUse,
} from "../../../../src/lib/record-display";
import {
  DESCRIPTION_MISSING_LABEL,
  excerptDescription,
  officialCveLink,
  recordTitle,
  severityBandFor,
} from "../../../../src/lib/search";
import type { EpssParam, KevParam, SeverityParam } from "./params";

// The record shape and its display derivations live in `src/lib/record-display.ts`
// so no library module ever imports route code. Re-exported here because this
// module is the record API every route already imports from.
export { exploitReferencesOf, kevRansomwareUseOf, legacyRansomwareKnown };
export type { FullRecord, KevRansomwareUse };

// The record walk lives in `src/lib/record-read.ts` so the AI tool layer can
// read records without importing route code. Re-exported here because this
// module is the record API every route already imports from.
export { loadFullRecords } from "../../../../src/lib/record-read";

export interface ApiCoverage {
  eligibleCohort: number;
  returned: number;
  unscored: number;
  unknownEpss: number;
  unknownDate: number;
}

export function coverageFor(items: readonly PriorityItem[], returned: number): ApiCoverage {
  let unscored = 0;
  let unknownEpss = 0;
  let unknownDate = 0;
  for (const item of items) {
    if (item.primary === null) unscored += 1;
    if (item.epss === null) unknownEpss += 1;
    if (item.publishedAt === null) unknownDate += 1;
  }
  return { eligibleCohort: items.length, returned, unscored, unknownEpss, unknownDate };
}

function excerptFields(record: FullRecord): {
  excerpt: string | null;
  excerptTruncated: boolean;
  excerptLanguage: string | null;
  excerptStatus: "present" | "fallback-language" | "not-supplied";
} {
  const shaped = excerptDescription(record.description, record.descriptionLang);
  if (shaped.excerpt === DESCRIPTION_MISSING_LABEL) {
    return {
      excerpt: null,
      excerptTruncated: false,
      excerptLanguage: null,
      excerptStatus: "not-supplied",
    };
  }
  if (shaped.langLabel === "en") {
    return {
      excerpt: shaped.excerpt,
      excerptTruncated: shaped.truncated,
      excerptLanguage: "en",
      excerptStatus: "present",
    };
  }
  return {
    excerpt: shaped.excerpt,
    excerptTruncated: shaped.truncated,
    excerptLanguage: shaped.langLabel,
    excerptStatus: "fallback-language",
  };
}

export function toCveItem(
  record: FullRecord,
  epssScoreDate: string | null,
  epssModel: string | null,
): Record<string, unknown> {
  const excerpt = excerptFields(record);
  const title = recordTitle(record.title, record.cveId);
  const epss =
    record.epssText === null
      ? { status: "unknown", value: null, percentile: null, scoreDate: null, modelVersion: null }
      : {
          status: "known",
          value: Number(record.epssText),
          percentile: record.epssPercentile === null ? null : Number(record.epssPercentile),
          scoreDate: epssScoreDate,
          modelVersion: record.epssModel ?? epssModel,
        };
  const cvssPrimary =
    record.primary !== null && record.primary.version !== "2.0"
      ? {
          status: "known",
          source: "cna",
          version: record.primary.version,
          baseScore: Number(record.primary.baseScore),
          vector: record.primary.vector,
        }
      : record.primary !== null
        ? {
            status: "legacy",
            source: "cna",
            version: record.primary.version,
            baseScore: Number(record.primary.baseScore),
            vector: record.primary.vector,
          }
        : record.hasAdp
          ? { status: "adp-only", source: null, version: null, baseScore: null, vector: null }
          : { status: "unknown", source: null, version: null, baseScore: null, vector: null };
  return {
    cveId: record.cveId,
    title,
    state: record.state,
    publishedAt: record.publishedAt,
    officialUrl: officialCveLink(record.cveId),
    excerpt: excerpt.excerpt,
    excerptTruncated: excerpt.excerptTruncated,
    excerptLanguage: excerpt.excerptLanguage,
    excerptStatus: excerpt.excerptStatus,
    kev: {
      listed: record.kevDateAdded !== null,
      dateAdded: record.kevDateAdded,
      dueDate: record.kevDueDate,
      requiredAction: record.kevRequiredAction,
      vulnerabilityName: record.kevVulnerabilityName,
      // Catalog-stated use: 1 -> known, 0 -> unknown (the catalog's own value),
      // NULL -> unstated. Neither state is ever negated into an absence claim.
      ransomwareUse: record.kevRansomwareUse,
      // Legacy alias for the same fact; unknown is false, unstated is null.
      ransomwareKnown: record.kevRansomwareKnown,
      cwes: record.kevCwes,
    },
    epss,
    cvssPrimary,
    cvssSecondary: record.cvssSecondary,
    ssvc: record.ssvc,
    exploitReferenceStatus: record.exploitReferences.length > 0 ? "tagged" : "none",
    exploitReferences: record.exploitReferences,
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value === "object" && value !== null) return value as Record<string, unknown>;
  return {};
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

export function detailExtras(
  rawJson: string | null,
  descriptionLang: string | null,
): {
  descriptionLanguages: string[];
  references: Array<{ url: string; container: string; provider: string | null }>;
} {
  const languages: string[] = [];
  const references: Array<{ url: string; container: string; provider: string | null }> = [];
  if (rawJson !== null) {
    try {
      const root = asRecord(JSON.parse(rawJson) as unknown);
      const containers = asRecord(root.containers);
      for (const container of ["cna", "adp"] as const) {
        const section = asRecord(containers[container]);
        const descriptions = Array.isArray(section.descriptions) ? section.descriptions : [];
        for (const entry of descriptions) {
          const lang = asString(asRecord(entry).lang);
          if (lang !== null && !languages.includes(lang)) languages.push(lang);
        }
        const refs = Array.isArray(section.references) ? section.references : [];
        for (const entry of refs) {
          const row = asRecord(entry);
          const url = asString(row.url);
          if (url === null || (!url.startsWith("https://") && !url.startsWith("http://"))) continue;
          references.push({ url, container, provider: asString(row.provider) });
        }
      }
    } catch {
      // Unparseable raw payloads degrade to the stored fields, never a throw.
    }
  }
  if (languages.length === 0 && descriptionLang !== null && descriptionLang !== "") {
    languages.push(descriptionLang);
  }
  return { descriptionLanguages: languages, references };
}

/** In-memory filter matching the explore-view semantics behind searchCves. */
export function filterPriorityItems(
  items: readonly PriorityItem[],
  filters: {
    severity: SeverityParam | null;
    kev: KevParam;
    epss: EpssParam;
    start: string | null;
    end: string | null;
  },
): PriorityItem[] {
  return items.filter((item) => {
    if (filters.kev === "listed" && !item.kevMember) return false;
    if (filters.kev === "not-listed" && item.kevMember) return false;
    if (filters.epss === "scored" && item.epss === null) return false;
    if (filters.epss === "unscored" && item.epss !== null) return false;
    if (filters.start !== null || filters.end !== null) {
      if (item.publishedAt === null) return false;
      if (filters.start !== null && item.publishedAt < filters.start) return false;
      if (filters.end !== null && item.publishedAt >= filters.end) return false;
    }
    if (filters.severity !== null && severityBandFor(item.primary) !== filters.severity)
      return false;
    return true;
  });
}

export function todayUtcDay(nowIso: string): string {
  return nowIso.slice(0, 10);
}
