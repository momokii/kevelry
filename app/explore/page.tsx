import path from "node:path";
import { unstable_cache } from "next/cache";

import { ExploreFilters } from "@/components/explore/ExploreFilters";
import { ExploreResults, type ExploreOutcome } from "@/components/explore/ExploreResults";
import { Masthead } from "@/components/ledger/Masthead";
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
  type EpssFilter,
  type KevFilter,
  type SearchResponse,
  type SeverityBand,
} from "@/lib/search";

export const revalidate = 60;

export const metadata = {
  title: "Explore CVE records",
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
// rescanning. Only fulfilled results are cached; validation and I/O
// failures propagate uncached every time.
const cachedExploreSearch = unstable_cache(
  async (dataDir: string, key: string): Promise<SearchResponse> => {
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
    return searchCves(db, {
      q: args.q === "" ? undefined : args.q,
      dateStart: args.dateStart === "" ? undefined : args.dateStart,
      dateEnd: args.dateEnd === "" ? undefined : args.dateEnd,
      severity: args.severity.length === 0 ? undefined : args.severity,
      kev: args.kev,
      epss: args.epss,
      limit: args.limit,
      cursor: args.cursor ?? undefined,
    });
  },
  ["explore-search-v1"],
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

    let response: SearchResponse | null = null;
    try {
      const dataDir = resolveDataDir();
      response = await cachedExploreSearch(
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
    if (response === null) {
      outcome = { kind: "unavailable" };
    } else {
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
      outcome = { kind: "results", response, filtered, nextHref, firstHref };
    }
  } catch (error) {
    if (error instanceof SearchValidationError) {
      outcome = invalid(error.message);
    } else {
      outcome = { kind: "unavailable" };
    }
  }

  return (
    <main className="ledger-page" data-testid="explore-root" id="main-content">
      <Masthead current="Search" testId="explore-masthead" />

      <h1 data-testid="explore-title">Explore CVE records</h1>
      <p className="ledger-meta" data-testid="explore-lede">
        Identifier and description search over the retained local snapshot. No upstream fetch;
        nickname matching is not promised. Publication filters use UTC date intervals.
      </p>

      <section className="ledger-section" aria-label="Search and filters">
        <ExploreFilters initial={initial} />
      </section>

      <section className="ledger-section" aria-label="Search outcome">
        <ExploreResults outcome={outcome} />
      </section>
    </main>
  );
}
