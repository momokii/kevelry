"use client";

import { useState } from "react";

import { ChartBars, type BarDatum } from "./ChartBars";
import { dayExploreHref, formatCount, monthExploreHref, monthLabel } from "./chartData";
import type { DayBucket } from "./loadOverview";

type VolumeView = "months" | "days";

type PublicationChartProps = {
  days: DayBucket[];
  total30: number;
  months: DayBucket[];
  totalMonths: number;
  publishedTotal: number;
  anchorDay: string | null;
  unknownDateCount: number;
  correctionNotes: string[];
};

function itemsFor(series: DayBucket[], view: VolumeView): BarDatum[] {
  return series.map((bucket) => ({
    key: bucket.bucketStart,
    label:
      view === "months"
        ? (monthLabel(bucket.bucketStart) ?? bucket.bucketStart)
        : bucket.bucketStart,
    count: bucket.count,
    href:
      view === "months"
        ? (monthExploreHref(bucket.bucketStart) ?? "/explore")
        : dayExploreHref(bucket.bucketStart),
  }));
}

export function PublicationChart({
  days,
  total30,
  months,
  totalMonths,
  publishedTotal,
  anchorDay,
  unknownDateCount,
  correctionNotes,
}: PublicationChartProps) {
  const [view, setView] = useState<VolumeView>("months");
  if (days.length === 0 && months.length === 0) {
    return (
      <div className="ledger-skeleton" data-testid="overview-chart-empty">
        Empty interval: no published records in the retained snapshot. This is an honest empty
        state, not a zero baseline.
      </div>
    );
  }
  const monthly = view === "months";
  const series = monthly ? months : days;
  const total = monthly ? totalMonths : total30;
  const items = itemsFor(series, view);
  const peak = series.reduce((max, bucket) => Math.max(max, bucket.count), 0);
  const peakBuckets = series.filter((bucket) => bucket.count === peak && peak > 0);
  const peakNote =
    peakBuckets.length === 0
      ? `No publications in this ${monthly ? "24-month" : "30-day"} window.`
      : `Peak ${formatCount(peak)} in ${peakBuckets.map((bucket) => bucket.bucketStart).join(", ")}.`;
  return (
    <div data-testid="overview-chart">
      <div
        className="ledger-filter-group"
        role="group"
        aria-label="Volume interval"
        data-testid="overview-chart-view-toggle"
      >
        <button
          type="button"
          className="ledger-filter-chip"
          aria-pressed={monthly}
          data-testid="overview-chart-view-months"
          onClick={() => setView("months")}
        >
          24 months
        </button>
        <button
          type="button"
          className="ledger-filter-chip"
          aria-pressed={!monthly}
          data-testid="overview-chart-view-days"
          onClick={() => setView("days")}
        >
          30 days
        </button>
      </div>
      <p className="ledger-meta" data-testid="overview-chart-summary">
        <span className="ledger-emphasis">
          {formatCount(total)} published in the last {monthly ? "24 months" : "30 UTC days"}
        </span>{" "}
        of {formatCount(publishedTotal)} published overall. {peakNote}{" "}
        <span className="ledger-caveat">
          {unknownDateCount === 0
            ? "No records sit in the explicit unknown-date bucket."
            : `${formatCount(unknownDateCount)} dated-unknown record(s) are shown separately below, never folded into dated bars.`}
        </span>
      </p>
      <ChartBars
        key={view}
        testId="overview-chart-volume"
        ariaLabel={`Published CVE volume by UTC ${monthly ? "month, last 24 months" : "day, last 30 days"}. Horizontal scroll region.`}
        items={items}
        denominator={publishedTotal}
        denominatorNoun="published"
        basis={
          monthly
            ? "Date basis: UTC calendar month. Monthly bars group each record's publication date without smoothing."
            : "Date basis: UTC calendar day, so a record published late evening locally may fall on the next UTC day."
        }
        peakNote={peakNote}
        emptyMessage="Empty interval: no published records in the retained snapshot."
      />
      <p className="ledger-meta" data-testid="overview-chart-unknown-bar">
        {unknownDateCount === 0
          ? "Unknown date: 0 in the explicit unknown bucket"
          : `Unknown date: ${formatCount(unknownDateCount)} in the explicit unknown bucket, excluded from dated bars`}
      </p>
      <details data-testid="overview-chart-table-details">
        <summary>View the 30-day data table</summary>
        <table className="ledger-chart-table" data-testid="overview-chart-table">
          <caption className="ledger-meta" data-testid="overview-chart-caption">
            {anchorDay === null
              ? "Publication counts by UTC calendar day."
              : `Publication counts by UTC calendar day for the 30 days ending ${anchorDay}. Unknown dates are excluded from dated bars.`}
          </caption>
          <thead>
            <tr>
              <th scope="col">UTC day</th>
              <th scope="col">Records</th>
            </tr>
          </thead>
          <tbody>
            {days.map((day) => (
              <tr key={day.bucketStart}>
                <th scope="row">{day.bucketStart}</th>
                <td data-testid={`overview-chart-count-${day.bucketStart}`}>
                  {day.count === 0 ? "0 in this interval" : `${day.count} published`}
                </td>
              </tr>
            ))}
            <tr>
              <th scope="row">Unknown date</th>
              <td data-testid="overview-chart-count-unknown">
                {unknownDateCount === 0
                  ? "0 in the explicit unknown bucket"
                  : `${unknownDateCount} in the explicit unknown bucket, excluded from dated bars`}
              </td>
            </tr>
          </tbody>
        </table>
      </details>
      <details data-testid="overview-chart-months-details">
        <summary>View the 24-month data table</summary>
        <table className="ledger-chart-table" data-testid="overview-chart-months-table">
          <caption className="ledger-meta">
            Publication counts by UTC calendar month, grouped from record publication dates.
          </caption>
          <thead>
            <tr>
              <th scope="col">UTC month</th>
              <th scope="col">Records</th>
            </tr>
          </thead>
          <tbody>
            {months.map((month) => (
              <tr key={month.bucketStart}>
                <th scope="row">{month.bucketStart}</th>
                <td>{month.count === 0 ? "0 in this interval" : `${month.count} published`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
      {correctionNotes.map((note) => (
        <p key={note} className="ledger-meta" data-testid="overview-chart-correction">
          Correction note: {note}
        </p>
      ))}
    </div>
  );
}
