import type { CohortFacets, SearchResponse } from "@/lib/search";
import { TimeText } from "@/components/ledger/TimeText";

import { SEVERITY_META, formatInt } from "../charts/chartTokens";
import { CohortVisualization, type CohortLinkParams } from "./CohortVisualization";
import {
  EXPLORE_DEFAULT_LIMIT,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  severitySignal,
} from "./filter-meta";

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
  const meta = SEVERITY_META[item.severityBand];
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
    <article className="result-row" data-testid="explore-row">
      <div className="result-rail">
        <span className={`badge badge-${item.severityBand}`}>{meta.short}</span>
        {item.kevMember ? <span className="badge badge-kev">KEV</span> : null}
        <span className="result-date">
          <TimeText value={item.datePublished} />
        </span>
      </div>
      <div className="result-body">
        <div className="result-title-line">
          <span className="mono result-id" data-testid="explore-row-id">
            {item.cveId}
          </span>
          <p className="result-title" data-testid="explore-row-title">
            {item.title}
          </p>
        </div>
        <p className="result-excerpt" data-testid="explore-row-excerpt">
          {item.excerpt}
        </p>
        <p className="result-meta" data-testid="explore-row-lang">
          Excerpt language: {item.langLabel}
          {item.excerptTruncated
            ? ". Shortened to 320 code points; full text retained locally."
            : "."}
        </p>
        <p className="sr-only" data-testid="explore-row-signals">
          {severity} {kev} {epss}
        </p>
        <p className="sr-only" data-testid="explore-row-dates">
          {published} {updated}
        </p>
        <div className="result-signal-line">
          <span className="signal-chip">
            <span className="signal-chip-label">CVSS</span>
            <strong>{item.primary?.baseScore ?? "—"}</strong>
            {item.primary?.version ? <span>v{item.primary.version}</span> : null}
          </span>
          <span className="signal-chip">
            <span className="signal-chip-label">KEV</span>
            <strong>{item.kevMember ? "Listed" : "Not listed"}</strong>
          </span>
          <span className="signal-chip">
            <span className="signal-chip-label">EPSS</span>
            <strong>{item.epssKnown ? "Present" : "Unavailable"}</strong>
          </span>
          <span className="signal-chip">
            <span className="signal-chip-label">Updated</span>
            <strong>
              <TimeText value={item.dateUpdated} />
            </strong>
          </span>
        </div>
      </div>
      <div className="result-action">
        <a className="btn btn-sm" href={item.officialLink} data-testid="explore-row-action">
          Official record
        </a>
      </div>
    </article>
  );
}

export function ExploreResults({ outcome }: { outcome: ExploreOutcome }) {
  if (outcome.kind === "unavailable") {
    return (
      <section aria-label="Results" data-testid="explore-results">
        <div className="notice" data-testid="explore-unavailable" role="status">
          <span>
            <strong>Snapshot unavailable.</strong> No retained snapshot is readable at this data
            directory, so there is nothing to search yet. Filters stay usable; results appear after
            the first accepted import.
          </span>
        </div>
      </section>
    );
  }

  if (outcome.kind === "invalid") {
    return (
      <section aria-label="Results" data-testid="explore-results">
        <p className="ledger-search-error" role="alert" data-testid="explore-invalid">
          {outcome.message} Typed text is kept in the form.
        </p>
      </section>
    );
  }

  const { response, facets, linkParams, filtered, nextHref, firstHref } = outcome;
  const from = response.total === 0 ? 0 : response.offset + 1;
  const to = response.offset + response.items.length;
  const bands = SEVERITY_ORDER.map(
    (band) => `${bandShort(band)} ${formatInt(response.coverage.bySeverity[band])}`,
  ).join(", ");

  return (
    <section aria-label="Results" data-testid="explore-results">
      <div className="explore-result-head">
        <div>
          <div className="eyebrow">Matching cohort</div>
          <p className="explore-count" data-testid="explore-coverage">
            Matching cohort: <strong>{formatInt(response.total)}</strong> published records
            <span className="muted">
              {" "}
              · {formatInt(response.coverage.kevMembers)} KEV ·{" "}
              {formatInt(response.coverage.epssKnown)} with a forecast ·{" "}
              {formatInt(response.coverage.unknownDate)} unknown dates
            </span>
          </p>
        </div>
        <details className="chart-info" data-testid="explore-ordering">
          <summary>Ordering &amp; coverage</summary>
          <div className="chart-info-panel">
            <strong>Search ordering:</strong> text queries rank by the local index, then CVE ID.
            Empty queries sort publication date descending with unknown dates last. Severity bands
            narrow the cohort after the text, date, and signal match. Excerpts are capped at 320
            code points. Coverage is exact over the matching cohort.
          </div>
        </details>
      </div>

      <CohortVisualization
        facets={facets}
        params={linkParams}
        defaultLimit={EXPLORE_DEFAULT_LIMIT}
      />

      <div className="explore-list-head">
        <span>
          Showing {from}–{to} of {formatInt(response.total)}
        </span>
        <span className="faint" data-testid="explore-coverage-bands">
          By severity band: {bands}
        </span>
      </div>

      {response.items.length === 0 ? (
        <div className="empty-state" data-testid="explore-empty" role="status">
          <strong>{filtered ? "No matches in this cohort" : "No published records yet"}</strong>
          {filtered
            ? "Try fewer filters or a shorter query."
            : "The retained snapshot is empty; nothing here is a zero or a guess."}
        </div>
      ) : (
        <div className="result-list" data-testid="explore-list">
          {response.items.map((item) => (
            <ResultRow key={item.cveId} item={item} />
          ))}
        </div>
      )}

      <nav aria-label="Result pages" data-testid="explore-pagination" className="pagination">
        <span className="muted" data-testid="explore-page-count">
          Showing {from} to {to} of {response.total}.
        </span>
        {firstHref !== null ? (
          <a className="btn btn-sm" href={firstHref} data-testid="explore-first">
            First page
          </a>
        ) : null}
        {nextHref !== null ? (
          <a className="btn btn-sm" href={nextHref} data-testid="explore-next">
            Next page
          </a>
        ) : (
          <span className="faint">No further pages.</span>
        )}
      </nav>
    </section>
  );
}
