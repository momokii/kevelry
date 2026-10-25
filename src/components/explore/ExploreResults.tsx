import type { CohortFacets, SearchResponse } from "@/lib/search";

import {
  EXPLORE_DEFAULT_LIMIT,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  severitySignal,
} from "./filter-meta";
import { CohortVisualization, type CohortLinkParams } from "./CohortVisualization";

export type ExploreOutcome =
  | { kind: "unavailable" }
  | { kind: "invalid"; message: string }
  | {
      kind: "results";
      response: SearchResponse;
      facets: CohortFacets;
      linkParams: CohortLinkParams;
      filtered: boolean;
      nextHref: string | null;
      firstHref: string | null;
    };

function bandShort(band: (typeof SEVERITY_ORDER)[number]): string {
  return SEVERITY_LABELS[band].split(",")[0] ?? band;
}

function ResultRow({ item }: { item: SearchResponse["items"][number] }) {
  const severity = severitySignal(
    item.severityBand,
    item.primary?.baseScore ?? null,
    item.primary?.version ?? null,
  );
  const kev = item.kevMember ? "KEV listed." : "Not listed in this KEV snapshot.";
  const epss = item.epssKnown
    ? "Forecast present in this snapshot."
    : "EPSS unavailable for this snapshot.";
  const published =
    item.datePublished === null
      ? "Publication date unknown; counted in the unknown-date bucket."
      : `Published ${item.datePublished}.`;
  const updated =
    item.dateUpdated === null ? "Updated date unknown." : `Updated ${item.dateUpdated}.`;
  return (
    <article className="ledger-row" data-testid="explore-row">
      <span className="ledger-row-id" data-testid="explore-row-id">
        {item.cveId}
      </span>
      <p className="ledger-row-title" data-testid="explore-row-title">
        {item.title}
      </p>
      <p className="ledger-row-title" data-testid="explore-row-excerpt">
        {item.excerpt}
      </p>
      <p className="ledger-meta" data-testid="explore-row-lang">
        Excerpt language: {item.langLabel}
        {item.excerptTruncated
          ? ". Shortened to 320 code points; full text retained locally."
          : "."}
      </p>
      <p className="ledger-row-signals" data-testid="explore-row-signals">
        {severity} {kev} {epss}
      </p>
      <p className="ledger-meta" data-testid="explore-row-dates">
        {published} {updated}
      </p>
      <a className="ledger-row-action" href={item.officialLink} data-testid="explore-row-action">
        Official CVE record
      </a>
    </article>
  );
}

/**
 * Results region: honest states only. React escapes every value, so hostile
 * query text and hostile stored descriptions render inert by construction.
 */
export function ExploreResults({ outcome }: { outcome: ExploreOutcome }) {
  if (outcome.kind === "unavailable") {
    return (
      <section aria-label="Results" data-testid="explore-results">
        <div className="ledger-notice" data-testid="explore-unavailable" role="status">
          <span>
            <strong>Snapshot unavailable.</strong> No retained snapshot is readable at this data
            directory, so there is nothing to search yet. Filters above stay usable; results appear
            after the first accepted import.
          </span>
        </div>
      </section>
    );
  }

  if (outcome.kind === "invalid") {
    return (
      <section aria-label="Results" data-testid="explore-results">
        <p className="ledger-search-error" role="alert" data-testid="explore-invalid">
          {outcome.message} Typed text is kept in the form above.
        </p>
      </section>
    );
  }

  const { response, facets, linkParams, filtered, nextHref, firstHref } = outcome;
  const from = response.total === 0 ? 0 : response.offset + 1;
  const to = response.offset + response.items.length;
  const bands = SEVERITY_ORDER.map(
    (band) => `${bandShort(band)} ${response.coverage.bySeverity[band]}`,
  ).join(", ");

  return (
    <section aria-label="Results" data-testid="explore-results">
      <div className="ledger-ordering" data-testid="explore-ordering">
        <strong>Search ordering: text queries rank by the local index, then CVE ID.</strong>
        <span className="ledger-meta">
          Empty queries sort publication date descending with unknown dates last, then CVE ID.
          Severity bands narrow the cohort after the text, date, and signal match. Excerpts are
          capped at 320 code points with the language labeled.
        </span>
      </div>

      <CohortVisualization
        facets={facets}
        params={linkParams}
        defaultLimit={EXPLORE_DEFAULT_LIMIT}
      />

      <p className="ledger-meta" role="status" data-testid="explore-coverage">
        Matching cohort: {response.total} published records. Unknown publication date:{" "}
        {response.coverage.unknownDate}. Unscored: {response.coverage.unknownSeverity}. Legacy v2.0
        only: {response.coverage.legacySeverity}. KEV-listed: {response.coverage.kevMembers}. With
        forecast: {response.coverage.epssKnown}.
      </p>
      <p className="ledger-meta" data-testid="explore-coverage-bands">
        By severity band: {bands}.
      </p>

      {response.items.length === 0 ? (
        <div className="ledger-notice" data-testid="explore-empty" role="status">
          <span>
            {filtered ? (
              <>
                <strong>No matches in the retained snapshot.</strong> Try fewer filters or a shorter
                query.
              </>
            ) : (
              <>
                <strong>No published records in the retained snapshot.</strong> The corpus is empty;
                nothing here is a zero or a guess.
              </>
            )}
          </span>
        </div>
      ) : (
        <div data-testid="explore-list">
          {response.items.map((item) => (
            <ResultRow key={item.cveId} item={item} />
          ))}
        </div>
      )}

      <nav
        aria-label="Result pages"
        data-testid="explore-pagination"
        className="ledger-explore-pages"
      >
        <span className="ledger-meta" data-testid="explore-page-count">
          Showing {from} to {to} of {response.total}.
        </span>
        {firstHref !== null ? (
          <a href={firstHref} data-testid="explore-first">
            First page
          </a>
        ) : null}
        {nextHref !== null ? (
          <a href={nextHref} data-testid="explore-next">
            Next page
          </a>
        ) : (
          <span className="ledger-meta">No further pages.</span>
        )}
      </nav>
    </section>
  );
}
