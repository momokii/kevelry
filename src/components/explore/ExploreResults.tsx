import type { CohortFacets, SearchResponse } from "@/lib/search";
import { TimeText } from "@/components/ledger/TimeText";
import { displayProbabilityPercent } from "@/lib/ranking";

import { SEVERITY_META, formatInt } from "../charts/chartTokens";
import { ExploitSignal } from "../ledger/ExploitSignal";
import { WatchStar } from "../ledger/WatchStar";
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
      /** Current page as an export link: same query, same cursor, page-bounded. */
      exportCsvHref: string;
      exportJsonHref: string;
    };

/**
 * EPSS ships its percentile as a 0..1 fraction. Rendered as a whole ordinal
 * ("33rd pct") because "0.33498 percentile" reads as a probability, which it is
 * not — it is a rank among scored CVEs.
 */
function percentileLabel(raw: string | null): string | null {
  if (raw === null) return null;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0 || value > 1) return null;
  const whole = Math.round(value * 100);
  const mod100 = whole % 100;
  const suffix =
    mod100 >= 11 && mod100 <= 13
      ? "th"
      : whole % 10 === 1
        ? "st"
        : whole % 10 === 2
          ? "nd"
          : whole % 10 === 3
            ? "rd"
            : "th";
  return `${whole}${suffix} pct`;
}

function bandShort(band: (typeof SEVERITY_ORDER)[number]): string {
  return SEVERITY_LABELS[band].split(",")[0] ?? band;
}

/**
 * Page-bounded export controls (v3 epic E5).
 *
 * Each control is a real link to the search endpoint with `format=`, carrying
 * the query string and cursor of the page on screen, so the file always equals
 * the visible rows. The label states the row count; provenance and coverage
 * stay in the JSON envelope, never in the CSV file. When the page cannot be
 * exported the control renders disabled with a visible explanation instead of
 * a link that would fail.
 */
function ExportControls({
  rowCount,
  csvHref,
  jsonHref,
  disabledReason,
}: {
  rowCount: number;
  csvHref: string;
  jsonHref: string;
  disabledReason: string | null;
}) {
  const count = `${formatInt(rowCount)} ${rowCount === 1 ? "row" : "rows"}`;
  const noteId = "explore-export-note";
  return (
    <div className="export-block" data-testid="explore-export">
      <div className="export-actions" role="group" aria-label="Export this page">
        {disabledReason === null ? (
          <>
            <a
              className="btn"
              href={csvHref}
              data-testid="explore-export-csv"
            >
              Export CSV ({count})
            </a>
            <a
              className="btn"
              href={jsonHref}
              data-testid="explore-export-json"
            >
              Export JSON ({count})
            </a>
          </>
        ) : (
          <>
            <button
              type="button"
              className="btn"
              disabled
              aria-describedby={noteId}
              data-testid="explore-export-csv"
              data-export-disabled="true"
            >
              Export CSV ({count})
            </button>
            <button
              type="button"
              className="btn"
              disabled
              aria-describedby={noteId}
              data-testid="explore-export-json"
              data-export-disabled="true"
            >
              Export JSON ({count})
            </button>
          </>
        )}
      </div>
      <p className="export-note" id={noteId} data-testid="explore-export-note">
        {disabledReason ??
          `Exports exactly this page (${count}), not the whole cohort. Provenance stays in the JSON envelope.`}
      </p>
    </div>
  );
}

function ResultRow({ item }: { item: SearchResponse["items"][number] }) {
  const meta = SEVERITY_META[item.severityBand];
  const severity = severitySignal(
    item.severityBand,
    item.primary?.baseScore ?? null,
    item.primary?.version ?? null,
  );
  const kev = item.kevMember ? "KEV listed." : "Not listed in this KEV snapshot.";
  // Same values Priority shows: the real probability and percentile instead of a
  // bare "present", so a reader never has to open another view for the number.
  const epssPercent = item.epssText === null ? null : displayProbabilityPercent(item.epssText);
  const epssLabel = epssPercent === null ? "Unavailable" : `${epssPercent}%`;
  const epssRank = percentileLabel(item.epssPercentile);
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
        {item.exploitTagged ? (
          <span
            className="badge badge-accent"
            title="A CVE reference carries the publisher's exploit tag: a classification, not a verified working exploit."
            data-testid="explore-row-exploit-badge"
          >
            exploit ref
          </span>
        ) : null}
        <span className="result-date">
          Published <TimeText value={item.datePublished} />
        </span>
      </div>
      <div className="result-body">
        <div className="result-title-line">
          <span className="result-id-row">
            <span className="mono result-id" data-testid="explore-row-id">
              {item.cveId}
            </span>
            <WatchStar cveId={item.cveId} testId={`explore-watch-${item.cveId}`} />
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
            {item.kevDateAdded === null ? null : (
              <span>
                added <TimeText value={item.kevDateAdded} />
              </span>
            )}
          </span>
          <span className="signal-chip">
            <span className="signal-chip-label">EPSS</span>
            <strong>{epssLabel}</strong>
            {epssRank === null ? null : <span>{epssRank}</span>}
          </span>
          <span className="signal-chip">
            <span className="signal-chip-label">Updated</span>
            <strong>
              <TimeText value={item.dateUpdated} />
            </strong>
          </span>
        </div>
        {item.exploitTagged ? (
          <ExploitSignal
            references={item.exploitReferences.map((url) => ({ url }))}
            listTestId="explore-row-exploit-list"
            helpTestId="explore-row-exploit-help"
            compact
          />
        ) : null}
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

  const { response, facets, linkParams, filtered, nextHref, firstHref, exportCsvHref, exportJsonHref } =
    outcome;
  const from = response.total === 0 ? 0 : response.offset + 1;
  const to = response.offset + response.items.length;
  const rowCount = response.items.length;
  // Export mode is the one documented exception to the `q` requirement: the
  // endpoint serializes the same unfiltered first page `/explore` renders, so
  // the control only explains itself when the page genuinely has no rows.
  const exportDisabledReason =
    rowCount === 0
      ? "Nothing to export: this page has no rows. Narrow or clear the filters until results appear."
      : null;
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
        <div className="explore-result-tools">
          <details className="chart-info" data-testid="explore-ordering">
            <summary>Ordering &amp; coverage</summary>
            <div className="chart-info-panel">
              <strong>Search ordering:</strong> text queries rank by the local index, then CVE ID.
              Empty queries sort publication date descending with unknown dates last. Severity
              bands narrow the cohort after the text, date, and signal match. Excerpts are capped
              at 320 code points. Coverage is exact over the matching cohort.
            </div>
          </details>
          <ExportControls
            rowCount={rowCount}
            csvHref={exportCsvHref}
            jsonHref={exportJsonHref}
            disabledReason={exportDisabledReason}
          />
        </div>
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
