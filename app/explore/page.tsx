import path from "node:path";
import { unstable_cache } from "next/cache";

import { FilterPanel } from "@/components/explore/FilterPanel";
import { PageHeader } from "@/components/shell/PageHeader";
import { ExploreResults, type ExploreOutcome } from "@/components/explore/ExploreResults";
import {
  EXPLORE_DEFAULT_LIMIT,
  ExploreInitial,
  isSeverityBand,
} from "@/components/explore/filter-meta";
import { openReadDatabase, readDatabaseSignature } from "@/lib/db";
import {
  MAX_SEARCH_LIMIT,
  SearchValidationError,
  searchCves,
  searchFacets,
  type CohortFacets,
  type EpssFilter,
  type KevFilter,
  type SearchResponse,
  type SeverityBand,
} from "@/lib/search";

export const revalidate = 60;

export const metadata = {
  title: "Explore CVE records — CVE Intel",
  description:
    "CVE identifier and description search with date, severity, KEV, and forecast filters over the retained local snapshot.",
};

type RawParams = Record<string, string | string[] | undefined>;

function firstValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function allValues(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function invalid(message: string): ExploreOutcome {
  return { kind: "invalid", message };
}

function parseLimit(raw: string | undefined): number {
  if (raw === undefined || raw === "") return EXPLORE_DEFAULT_LIMIT;
  if (!/^[0-9]+$/.test(raw)) {
    throw new SearchValidationError(
      `Search "limit" must be an integer in [1, ${MAX_SEARCH_LIMIT}].`,
    );
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_SEARCH_LIMIT) {
    throw new SearchValidationError(
      `Search "limit" must be an integer in [1, ${MAX_SEARCH_LIMIT}].`,
    );
  }
  return value;
}

function parseKev(raw: string | undefined): KevFilter {
  if (raw === undefined || raw === "" || raw === "all") return "all";
  if (raw === "only" || raw === "excluded") return raw;
  throw new SearchValidationError('Search "kev" must be "only", "excluded", or "all".');
}

function parseEpss(raw: string | undefined): EpssFilter {
  if (raw === undefined || raw === "" || raw === "all") return "all";
  if (raw === "present" || raw === "absent") return raw;
  throw new SearchValidationError('Search "epss" must be "present", "absent", or "all".');
}

function parseSeverity(raw: string[]): SeverityBand[] {
  const bands: SeverityBand[] = [];
  for (const chunk of raw) {
    for (const part of chunk.split(",")) {
      const band = part.trim();
      if (band === "") continue;
      if (!isSeverityBand(band)) {
        throw new SearchValidationError(`Unknown severity band: ${band.slice(0, 32)}.`);
      }
      if (!bands.includes(band)) bands.push(band);
    }
  }
  return bands;
}

function hrefWith(params: URLSearchParams): string {
  const text = params.toString();
  return text === "" ? "/explore" : `/explore?${text}`;
}

// Param-keyed result cache (60s, same staleness as the page revalidate):
// the unfiltered explore scan materializes the full corpus per render, so
// repeats with identical filters serve the retained snapshot instead of
// rescanning. The listing page plus the full-cohort facets resolve together
// so chart repeats stay cheap. Only fulfilled results are cached; validation
// and I/O failures propagate uncached every time.
const cachedExploreSearch = unstable_cache(
  async (
    dataDir: string,
    key: string,
  ): Promise<{ response: SearchResponse; facets: CohortFacets }> => {
    const args = JSON.parse(key) as {
      q: string;
      dateStart: string;
      dateEnd: string;
      severity: SeverityBand[];
      kev: KevFilter;
      epss: EpssFilter;
      limit: number;
      cursor: string | null;
      dbSignature: string;
    };
    const db = openReadDatabase(dataDir);
    const shared = {
      q: args.q === "" ? undefined : args.q,
      dateStart: args.dateStart === "" ? undefined : args.dateStart,
      dateEnd: args.dateEnd === "" ? undefined : args.dateEnd,
      severity: args.severity.length === 0 ? undefined : args.severity,
      kev: args.kev,
      epss: args.epss,
      limit: args.limit,
    };
    const response = searchCves(db, { ...shared, cursor: args.cursor ?? undefined });
    const facets = searchFacets(db, shared, response.coverage);
    return { response, facets };
  },
  ["explore-search-v2"],
  { revalidate: 60 },
);

function resolveDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") {
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
  }
  return path.join(process.cwd(), "data");
}

export default async function ExplorePage({ searchParams }: { searchParams?: Promise<RawParams> }) {
  const params: RawParams = (await searchParams) ?? {};
  const q = firstValue(params.q) ?? "";
  const dateStart = firstValue(params.dateStart) ?? "";
  const dateEnd = firstValue(params.dateEnd) ?? "";
  const cursor = firstValue(params.cursor) ?? undefined;

  const initial: ExploreInitial = {
    q,
    dateStart,
    dateEnd,
    severity: [],
    kev: "all",
    epss: "all",
    limit: EXPLORE_DEFAULT_LIMIT,
  };

  let outcome: ExploreOutcome;
  try {
    const severity = parseSeverity(allValues(params.severity));
    const kev = parseKev(firstValue(params.kev));
    const epss = parseEpss(firstValue(params.epss));
    const limit = parseLimit(firstValue(params.limit));
    initial.severity = severity;
    initial.kev = kev;
    initial.epss = epss;
    initial.limit = limit;

    let cached: { response: SearchResponse; facets: CohortFacets } | null = null;
    try {
      const dataDir = resolveDataDir();
      cached = await cachedExploreSearch(
        dataDir,
        JSON.stringify({
          q,
          dateStart,
          dateEnd,
          severity,
          kev,
          epss,
          limit,
          cursor: cursor ?? null,
          dbSignature: readDatabaseSignature(dataDir),
        }),
      );
    } catch (error) {
      if (error instanceof SearchValidationError) {
        throw error;
      }
    }
    if (cached === null) {
      outcome = { kind: "unavailable" };
    } else {
      const { response, facets } = cached;
      const filtered =
        q !== "" ||
        dateStart !== "" ||
        dateEnd !== "" ||
        severity.length > 0 ||
        kev !== "all" ||
        epss !== "all";
      const kept = new URLSearchParams();
      if (q !== "") kept.set("q", q);
      if (dateStart !== "") kept.set("dateStart", dateStart);
      if (dateEnd !== "") kept.set("dateEnd", dateEnd);
      for (const band of severity) kept.append("severity", band);
      if (kev !== "all") kept.set("kev", kev);
      if (epss !== "all") kept.set("epss", epss);
      if (limit !== EXPLORE_DEFAULT_LIMIT) kept.set("limit", String(limit));
      const nextHref =
        response.nextCursor === null
          ? null
          : hrefWith(new URLSearchParams([...kept.entries(), ["cursor", response.nextCursor]]));
      const firstHref = response.offset > 0 ? hrefWith(kept) : null;
      outcome = {
        kind: "results",
        response,
        facets,
        linkParams: { q, dateStart, dateEnd, severity, kev, epss, limit },
        filtered,
        nextHref,
        firstHref,
      };
    }
  } catch (error) {
    if (error instanceof SearchValidationError) {
      outcome = invalid(error.message);
    } else {
      outcome = { kind: "unavailable" };
    }
  }

  return (
    <main className="page" data-testid="explore-root" id="main-content">
      <PageHeader
        eyebrow={
          <>
            <span>Search</span>
            <span className="dot" aria-hidden="true" />
            <span>Retained snapshot</span>
            <span className="dot" aria-hidden="true" />
            <span>UTC filters</span>
          </>
        }
        title={<span data-testid="explore-title">Find the CVE cohort</span>}
        lede={
          <span data-testid="explore-lede">
            Identifier and description search over the retained local snapshot. Filters apply to the
            cohort immediately; every chart links back into the same filter state.
          </span>
        }
        actions={
          <>
            <a className="btn btn-sm" href="/methodology#methodology-section-signals">
              Scoring rules
            </a>
            <a className="btn btn-primary btn-sm" href="/api-docs">
              API reference
            </a>
          </>
        }
      />

      <div className="explore-layout">
        <aside className="explore-sidebar" aria-label="Search and filters">
          <FilterPanel initial={initial} />
        </aside>
        <div className="explore-main">
          <ExploreResults outcome={outcome} />
        </div>
      </div>
    </main>
  );
}
