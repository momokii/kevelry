import type { CohortFacets, EpssFilter, KevFilter, SeverityBand } from "@/lib/search";

import { SEVERITY_META, SEVERITY_ORDER, formatInt, sharePercent } from "../charts/chartTokens";
import { monthShort } from "../charts/chartTokens";
import { SEVERITY_LABELS } from "./filter-meta";

export interface CohortLinkParams {
  q: string;
  dateStart: string;
  dateEnd: string;
  severity: readonly SeverityBand[];
  kev: KevFilter;
  epss: EpssFilter;
  limit: number;
}

type CohortVisualizationProps = {
  facets: CohortFacets;
  params: CohortLinkParams;
  defaultLimit: number;
};

function baseKept(params: CohortLinkParams, defaultLimit: number): URLSearchParams {
  const next = new URLSearchParams();
  if (params.q !== "") next.set("q", params.q);
  if (params.dateStart !== "") next.set("dateStart", params.dateStart);
  if (params.dateEnd !== "") next.set("dateEnd", params.dateEnd);
  for (const band of params.severity) next.append("severity", band);
  if (params.kev !== "all") next.set("kev", params.kev);
  if (params.epss !== "all") next.set("epss", params.epss);
  if (params.limit !== defaultLimit) next.set("limit", String(params.limit));
  return next;
}

function severityHref(params: CohortLinkParams, defaultLimit: number, band: SeverityBand): string {
  const next = baseKept(params, defaultLimit);
  next.delete("severity");
  next.append("severity", band);
  const text = next.toString();
  return text === "" ? "/explore" : `/explore?${text}`;
}

const MONTH_PATTERN = /^(\d{4})-(0[1-9]|1[0-2])$/;

function monthBounds(month: string): { start: string; end: string } | null {
  const parts = month.match(MONTH_PATTERN);
  if (parts === null || parts[1] === undefined || parts[2] === undefined) return null;
  const year = Number(parts[1]);
  const value = Number(parts[2]);
  const start = `${month}-01`;
  const end =
    value === 12 ? `${year + 1}-01-01` : `${parts[1]}-${String(value + 1).padStart(2, "0")}-01`;
  return { start, end };
}

function monthHref(params: CohortLinkParams, defaultLimit: number, month: string): string | null {
  const bounds = monthBounds(month);
  if (bounds === null) return null;
  const next = baseKept(params, defaultLimit);
  next.set("dateStart", bounds.start);
  next.set("dateEnd", bounds.end);
  const text = next.toString();
  return text === "" ? "/explore" : `/explore?${text}`;
}

export function CohortVisualization({ facets, params, defaultLimit }: CohortVisualizationProps) {
  const total = facets.total;
  const peakMonth = facets.byMonth.reduce((max, entry) => Math.max(max, entry.count), 0);

  return (
    <section
      className="cohort"
      aria-label="Matching cohort visualization"
      data-testid="explore-cohort"
    >
      <h2 className="sr-only">Matching cohort composition</h2>
      <div className="cohort-head">
        <div>
          <div className="eyebrow">Cohort composition</div>
          <p className="cohort-headline" data-testid="explore-cohort-headline">
            <strong>{formatInt(total)}</strong> matching published records
            <span className="muted">
              {" "}
              · {formatInt(facets.unknownDate)} with an unknown publication date
            </span>
          </p>
        </div>
        <p className="chart-note" style={{ margin: 0 }}>
          Every segment and month is a link that preserves the other filters.
        </p>
      </div>

      {total === 0 ? (
        <p className="empty-state" data-testid="explore-cohort-empty">
          <strong>No records match this cohort</strong>
          There is nothing to chart. Counts are exact; nothing here is a zero or a guess.
        </p>
      ) : (
        <div className="cohort-grid">
          <div className="cohort-block">
            <h3>Severity</h3>
            <ul className="severity-list" data-testid="explore-cohort-severity">
              {SEVERITY_ORDER.map((band) => {
                const meta = SEVERITY_META[band];
                const count = facets.bySeverity[band];
                return (
                  <li key={band}>
                    <a
                      className="severity-row"
                      href={severityHref(params, defaultLimit, band)}
                      data-testid={`explore-cohort-severity-${band}`}
                      title={`${SEVERITY_LABELS[band]}: ${formatInt(count)} (${sharePercent(count, total)} of the cohort). Show only this band.`}
                      aria-label={`${SEVERITY_LABELS[band]}: ${formatInt(count)}, ${sharePercent(count, total)} of the cohort. Show only this band.`}
                    >
                      <span className="severity-label">
                        <span
                          className="severity-dot"
                          style={{ background: meta.color }}
                          aria-hidden="true"
                        />
                        {meta.short}
                      </span>
                      <span className="severity-track" aria-hidden="true">
                        <span
                          className="severity-fill"
                          style={{
                            width: `${Math.max(count > 0 ? 0.6 : 0, (count / total) * 100)}%`,
                            background: meta.color,
                          }}
                        />
                      </span>
                      <span className="severity-value">
                        <strong>{formatInt(count)}</strong>
                        {sharePercent(count, total)}
                      </span>
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="cohort-block">
            <h3>Matching records by UTC month</h3>
            <ul className="cohort-months" data-testid="explore-cohort-months">
              {facets.byMonth.map((entry) => {
                const href = monthHref(params, defaultLimit, entry.month);
                if (href === null) return null;
                return (
                  <li key={entry.month}>
                    <a
                      className="cohort-month"
                      href={href}
                      data-testid={`explore-cohort-month-${entry.month}`}
                      title={`${monthShort(entry.month)}: ${formatInt(entry.count)} matching records (${sharePercent(entry.count, total)}). Show only this month.`}
                      aria-label={`${monthShort(entry.month)}: ${formatInt(entry.count)} records, ${sharePercent(entry.count, total)} of the cohort. Show only this month.`}
                    >
                      <span className="cohort-month-label">{monthShort(entry.month)}</span>
                      <span className="cohort-month-track" aria-hidden="true">
                        <span
                          className="cohort-month-fill"
                          style={{
                            width: `${peakMonth > 0 ? (entry.count / peakMonth) * 100 : 0}%`,
                          }}
                        />
                      </span>
                      <span className="cohort-month-count">{formatInt(entry.count)}</span>
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="cohort-block">
            <h3>Signal coverage</h3>
            <dl className="cohort-stats">
              <div>
                <dt>KEV-listed</dt>
                <dd>{formatInt(facets.kevMembers)}</dd>
              </div>
              <div>
                <dt>With a forecast</dt>
                <dd>{formatInt(facets.epssKnown)}</dd>
              </div>
              <div>
                <dt>Unknown date</dt>
                <dd>{formatInt(facets.unknownDate)}</dd>
              </div>
              <div>
                <dt>Unscored severity</dt>
                <dd>{formatInt(facets.bySeverity.unknown)}</dd>
              </div>
            </dl>
            <p className="chart-note">
              Share of cohort: KEV {sharePercent(facets.kevMembers, total)} · forecast{" "}
              {sharePercent(facets.epssKnown, total)} · unscored{" "}
              {sharePercent(facets.bySeverity.unknown, total)}.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}
