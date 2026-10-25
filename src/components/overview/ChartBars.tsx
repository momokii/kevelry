"use client";

import { useState } from "react";
import type { CSSProperties } from "react";

import { formatCount, publishedShare } from "./chartData";
import styles from "./charts.module.css";

export interface BarDatum {
  key: string;
  label: string;
  count: number;
  href: string;
}

type ChartBarsProps = {
  testId: string;
  ariaLabel: string;
  items: BarDatum[];
  /** Population the per-bar share is computed against. */
  denominator: number;
  /** What `denominator` counts, e.g. "published", "scored forecasts". */
  denominatorNoun: string;
  basis: string;
  peakNote?: string | null;
  emptyMessage: string;
  actionLabel?: string;
};

function barHeight(count: number, peak: number): number {
  if (peak <= 0) return 8;
  return Math.round(8 + (count / peak) * 88);
}

export function ChartBars({
  testId,
  ariaLabel,
  items,
  denominator,
  denominatorNoun,
  basis,
  peakNote = null,
  emptyMessage,
  actionLabel = "Activate to open the filtered view",
}: ChartBarsProps) {
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const active = items.find((item) => item.key === activeKey) ?? null;
  const peak = items.reduce((max, item) => Math.max(max, item.count), 0);
  const peakKeys = new Set(
    items.filter((item) => item.count === peak && peak > 0).map((item) => item.key),
  );

  if (items.length === 0) {
    return (
      <p className="ledger-skeleton" data-testid={`${testId}-empty`}>
        {emptyMessage}
      </p>
    );
  }

  return (
    <div data-testid={testId}>
      <p className={styles.scrollHint} data-testid={`${testId}-scroll-hint`}>
        Scroll horizontally to reach every bar; every bar is a link to the filtered view.
      </p>
      <div className={styles.tooltip} data-testid={`${testId}-tooltip`}>
        {active === null ? (
          <span className={styles.tooltipIdle}>
            Hover or Tab to a bar to inspect it. {basis}
            {peakNote !== null ? ` ${peakNote}` : null}
          </span>
        ) : (
          <span>
            <strong>
              {active.label}:{" "}
              {active.count === 0 ? "0 in this interval" : formatCount(active.count)}
            </strong>{" "}
            <span className="ledger-meta">
              ({publishedShare(active.count, denominator, denominatorNoun)}).
            </span>{" "}
            <span className="ledger-caveat">{basis}</span>
          </span>
        )}
      </div>
      <div className={styles.scrollRegion} role="group" aria-label={ariaLabel}>
        <div className={styles.bars} data-testid={`${testId}-bars`}>
          {items.map((item) => (
            <a
              key={item.key}
              href={item.href}
              className={[
                styles.barLink,
                peakKeys.has(item.key) ? styles.barLinkPeak : "",
                item.count === 0 ? styles.barLinkZero : "",
              ].join(" ")}
              style={{ "--bar-height": `${barHeight(item.count, peak)}px` } as CSSProperties}
              aria-label={`${item.label}: ${publishedShare(item.count, denominator, denominatorNoun)}. ${basis} ${actionLabel}.`}
              data-testid={`${testId}-bar-${item.key}`}
              onMouseEnter={() => setActiveKey(item.key)}
              onMouseLeave={() =>
                setActiveKey((current) => (current === item.key ? null : current))
              }
              onFocus={() => setActiveKey(item.key)}
              onBlur={() => setActiveKey((current) => (current === item.key ? null : current))}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  setActiveKey(null);
                  event.currentTarget.blur();
                }
              }}
            >
              <span className={styles.barFill} aria-hidden="true" />
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
