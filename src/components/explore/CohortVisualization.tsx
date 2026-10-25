import type { CSSProperties } from "react";

import type { CohortFacets, EpssFilter, KevFilter, SeverityBand } from "@/lib/search";

import { SEVERITY_LABELS, SEVERITY_ORDER } from "./filter-meta";
import styles from "./cohort.module.css";

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

function formatTotal(total: number): string {
  return total.toLocaleString("en-US");
}

function shareText(count: number, total: number): string {
  if (total <= 0) return `0% of 0 matching records`;
  const percent = ((count / total) * 100).toFixed(1);
  return `${percent}% of ${formatTotal(total)} matching records`;
}

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

function severityHref(
  params: CohortLinkParams,
  defaultLimit: number,
  band: SeverityBand,
): string {
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

/**
 * Filter-driven cohort picture: every figure comes from searchFacets over
 * the currently applied filters, and every bar or segment is a link that
 * rewrites exactly one filter dimension while keeping the rest.
 */
export function CohortVisualization({ facets, params, defaultLimit }: CohortVisualizationProps) {
  const total = facets.total;
  const peakMonth = facets.byMonth.reduce((max, entry) => Math.max(max, entry.count), 0);

  return (
    <section aria-label="Matching cohort visualization" data-testid="explore-cohort">
      <p className="ledger-meta" data-testid="explore-cohort-headline">
        <span className="ledger-emphasis">{formatTotal(total)} matching published records.</span>{" "}
        <span className="ledger-caveat">
          Unknown publication date: {formatTotal(facets.unknownDate)}; those records are counted
          here and below but never appear in the monthly chart.
        </span>
      </p>

      {total === 0 ? (
        <p className="ledger-meta" data-testid="explore-cohort-empty">
          No records match the current filters, so there is nothing to chart. Counts are exact;
          nothing here is a zero or a guess.
        </p>
      ) : (
        <>
          <div data-testid="explore-cohort-severity">
            <p className="ledger-meta">
              <span className="ledger-label">Severity composition. </span>
              Every segment is a link that shows only that band while keeping the other filters.
            </p>
            <div
              className={styles.stackBar}
              role="group"
              aria-label="Matching records by severity band"
            >
              {SEVERITY_ORDER.map((band) => {
                const count = facets.bySeverity[band];
                const label = `${SEVERITY_LABELS[band]}: ${formatTotal(count)} (${shareText(count, total)}). Show only this band.`;
                return (
                  <a
                    key={band}
                    href={severityHref(params, defaultLimit, band)}
                    className={
                      band === "critical"
                        ? `${styles.segment} ${styles.segmentCritical}`
                        : styles.segment
                    }
                    style={{ flexGrow: count } as CSSProperties}
                    title={label}
                    aria-label={label}
                    data-testid={`explore-cohort-severity-${band}`}
                  >
                    {formatTotal(count)}
                  </a>
                );
              })}
            </div>
            <ul className={styles.legend} data-testid="explore-cohort-severity-legend">
              {SEVERITY_ORDER.map((band) => {
                const count = facets.bySeverity[band];
                return (
                  <li key={band} className={styles.legendItem}>
                    <a
                      href={severityHref(params, defaultLimit, band)}
                      className={styles.legendLink}
                      title={`${SEVERITY_LABELS[band]}: ${formatTotal(count)} (${shareText(count, total)}). Show only this band.`}
                      data-testid={`explore-cohort-legend-${band}`}
                    >
                      {SEVERITY_LABELS[band]}: {formatTotal(count)} ({shareText(count, total)})
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>

          <div data-testid="explore-cohort-months">
            <p className="ledger-meta">
              <span className="ledger-label">Monthly matching counts, UTC month. </span>
              Every row is a link that sets the date range to that month while keeping the other
              filters.
            </p>
            {facets.byMonth.length === 0 ? (
              <p className="ledger-meta" data-testid="explore-cohort-months-empty">
                No dated records in this cohort, so there is no month to chart.
              </p>
            ) : (
              <ul className={styles.months}>
                {facets.byMonth.map(({ month, count }) => {
                  const href = monthHref(params, defaultLimit, month);
                  if (href === null) return null;
                  const label = `${month}: ${formatTotal(count)} (${shareText(count, total)}). Show only ${month}.`;
                  const width = peakMonth > 0 ? Math.max(2, (count / peakMonth) * 100) : 0;
                  return (
                    <li key={month}>
                      <a
                        href={href}
                        className={
                          count === peakMonth && peakMonth > 0
                            ? `${styles.monthLink} ${styles.monthPeak}`
                            : styles.monthLink
                        }
                        title={label}
                        aria-label={label}
                        data-testid={`explore-cohort-month-${month}`}
                      >
                        <span className={styles.monthLabel}>{month}</span>
                        <span className={styles.monthTrack} aria-hidden="true">
                          <span className={styles.monthFill} style={{ width: `${width}%` }} />
                        </span>
                        <span className={styles.monthCount}>
                          {formatTotal(count)} ({shareText(count, total)})
                        </span>
                      </a>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <ul className={styles.stats} data-testid="explore-cohort-stats">
            <li className={styles.statItem} data-testid="explore-cohort-stat-kev">
              <span className="ledger-label">KEV-listed </span>
              <span className="ledger-emphasis">{formatTotal(facets.kevMembers)}</span>{" "}
              <span className="ledger-caveat">({shareText(facets.kevMembers, total)})</span>
            </li>
            <li className={styles.statItem} data-testid="explore-cohort-stat-epss">
              <span className="ledger-label">With forecast </span>
              <span className="ledger-emphasis">{formatTotal(facets.epssKnown)}</span>{" "}
              <span className="ledger-caveat">({shareText(facets.epssKnown, total)})</span>
            </li>
            <li className={styles.statItem} data-testid="explore-cohort-stat-unknown">
              <span className="ledger-label">Unknown publication date </span>
              <span className="ledger-emphasis">{formatTotal(facets.unknownDate)}</span>{" "}
              <span className="ledger-caveat">({shareText(facets.unknownDate, total)})</span>
            </li>
          </ul>
        </>
      )}
    </section>
  );
}
