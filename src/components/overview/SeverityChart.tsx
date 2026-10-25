"use client";

import { useState } from "react";

import {
  SEVERITY_PRIMARY_BANDS,
  severityExploreHref,
  publishedShare,
  type SeverityRow,
} from "./chartData";
import styles from "./charts.module.css";

type SeverityChartProps = {
  rows: SeverityRow[];
  publishedTotal: number;
};

export function SeverityChart({ rows, publishedTotal }: SeverityChartProps) {
  const [activeBand, setActiveBand] = useState<string | null>(null);
  const active = rows.find((row) => row.band === activeBand) ?? null;
  const primary = rows.filter((row) =>
    (SEVERITY_PRIMARY_BANDS as readonly string[]).includes(row.band),
  );
  const extra = rows.filter(
    (row) => !(SEVERITY_PRIMARY_BANDS as readonly string[]).includes(row.band),
  );
  const total = rows.reduce((sum, row) => sum + row.count, 0);

  if (rows.length === 0 || total === 0) {
    return (
      <p className="ledger-skeleton" data-testid="overview-severity-empty">
        0 in this interval: no scored or unscored records in the retained snapshot.
      </p>
    );
  }

  const clearIfActive = (band: string) => {
    setActiveBand((current) => (current === band ? null : current));
  };

  return (
    <div data-testid="overview-severity">
      <div className={styles.tooltip} data-testid="overview-severity-tooltip">
        {active === null ? (
          <span className={styles.tooltipIdle}>
            Hover or Tab to a band to inspect it. Severity comes from the primary CNA CVSS score;
            share is of {publishedTotal === 0 ? "0" : publishedTotal.toLocaleString("en-US")}{" "}
            published.
          </span>
        ) : (
          <span>
            <strong>
              {active.label}:{" "}
              {active.count === 0
                ? "0 in this interval"
                : `${active.count.toLocaleString("en-US")} published`}
            </strong>{" "}
            <span className="ledger-meta">({publishedShare(active.count, publishedTotal)}).</span>{" "}
            <span className="ledger-caveat">
              Primary CNA CVSS only; records with no CNA metric are Unscored, even when another
              source scored them.
            </span>
          </span>
        )}
      </div>
      <div
        className={styles.stackBar}
        role="group"
        aria-label="Severity mix as a horizontal stacked bar. Every segment is a link."
        data-testid="overview-severity-bars"
      >
        {rows.map((row) => (
          <a
            key={row.band}
            href={severityExploreHref(row.band)}
            className={
              row.band === "critical"
                ? `${styles.stackSegment} ${styles.stackSegmentCritical}`
                : styles.stackSegment
            }
            style={{ flexGrow: row.count, flexBasis: 0 }}
            aria-label={`${row.label}: ${publishedShare(row.count, publishedTotal)}. Activate to filter Explore by ${row.band}.`}
            data-testid={`overview-severity-bar-${row.band}`}
            onMouseEnter={() => setActiveBand(row.band)}
            onMouseLeave={() => clearIfActive(row.band)}
            onFocus={() => setActiveBand(row.band)}
            onBlur={() => clearIfActive(row.band)}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                setActiveBand(null);
                event.currentTarget.blur();
              }
            }}
          >
            {row.count > 0 ? row.label : null}
          </a>
        ))}
      </div>
      <ul className={styles.legend} data-testid="overview-severity-legend">
        {primary.map((row) => (
          <li key={row.band} className={styles.legendItem}>
            <span className={styles.swatch} aria-hidden="true" />
            <a
              href={severityExploreHref(row.band)}
              data-testid={`overview-severity-link-${row.band}`}
            >
              <span className="ledger-label">{row.label}</span>
            </a>{" "}
            <span className="ledger-emphasis">{row.count.toLocaleString("en-US")}</span>{" "}
            <span className="ledger-meta">({publishedShare(row.count, publishedTotal)})</span>
          </li>
        ))}
        {extra.map((row) => (
          <li key={row.band} className={styles.legendItem}>
            <span className={styles.swatch} aria-hidden="true" />
            <a
              href={severityExploreHref(row.band)}
              data-testid={`overview-severity-link-${row.band}`}
            >
              <span className="ledger-label">{row.label}</span>
            </a>{" "}
            <span className="ledger-emphasis">{row.count.toLocaleString("en-US")}</span>{" "}
            <span className="ledger-meta">({publishedShare(row.count, publishedTotal)})</span>
          </li>
        ))}
      </ul>
      <p className="ledger-meta" data-testid="overview-severity-note">
        <span className="ledger-caveat">
          Unscored means no primary CNA metric, not safe. Severity filters exclude unscored records
          by policy.
        </span>
      </p>
    </div>
  );
}
