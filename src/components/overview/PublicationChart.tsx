import { ChartBars, type BarDatum } from "./ChartBars";
import { dayExploreHref, formatCount } from "./chartData";
import type { DayBucket } from "./loadOverview";

type PublicationChartProps = {
  days: DayBucket[];
  total30: number;
  publishedTotal: number;
  anchorDay: string | null;
  unknownDateCount: number;
  correctionNotes: string[];
};

export function PublicationChart({
  days,
  total30,
  publishedTotal,
  anchorDay,
  unknownDateCount,
  correctionNotes,
}: PublicationChartProps) {
  if (days.length === 0) {
    return (
      <div className="ledger-skeleton" data-testid="overview-chart-empty">
        Empty interval: no published records in the retained snapshot. This is an honest empty
        state, not a zero baseline.
      </div>
    );
  }
  const peak = days.reduce((max, day) => Math.max(max, day.count), 0);
  const peakDays = days.filter((day) => day.count === peak && peak > 0);
  const items: BarDatum[] = days.map((day) => ({
    key: day.bucketStart,
    label: day.bucketStart,
    count: day.count,
    href: dayExploreHref(day.bucketStart),
  }));
  const peakNote =
    peakDays.length === 0
      ? "No publications in this 30-day window."
      : `Peak ${formatCount(peak)} on ${peakDays.map((day) => day.bucketStart).join(", ")}.`;
  return (
    <div data-testid="overview-chart">
      <p className="ledger-meta" data-testid="overview-chart-summary">
        <span className="ledger-emphasis">
          {formatCount(total30)} published in the last 30 UTC days
        </span>{" "}
        of {formatCount(publishedTotal)} published overall. {peakNote}{" "}
        <span className="ledger-caveat">
          {unknownDateCount === 0
            ? "No records sit in the explicit unknown-date bucket."
            : `${formatCount(unknownDateCount)} dated-unknown record(s) are shown separately below, never folded into dated bars.`}
        </span>
      </p>
      <ChartBars
        testId="overview-chart-volume"
        ariaLabel="Published CVE volume by UTC day, last 30 days. Horizontal scroll region."
        items={items}
        denominator={publishedTotal}
        denominatorNoun="published"
        basis="Date basis: UTC calendar day, so a record published late evening locally may fall on the next UTC day."
        peakNote={peakNote}
        emptyMessage="Empty interval: no published records in the retained snapshot."
      />
      <p className="ledger-meta" data-testid="overview-chart-unknown-bar">
        {unknownDateCount === 0
          ? "Unknown date: 0 in the explicit unknown bucket"
          : `Unknown date: ${formatCount(unknownDateCount)} in the explicit unknown bucket, excluded from dated bars`}
      </p>
      <table className="ledger-chart-table" data-testid="overview-chart-table">
        <caption className="ledger-meta" data-testid="overview-chart-caption">
          {anchorDay === null
            ? "Publication counts by UTC calendar day."
            : `Publication counts by UTC calendar day for the 30 days ending ${anchorDay}. Unknown dates are excluded from dated bars.`}
        </caption>
        <thead>
          <tr>
            <th scope="col">UTC bucket</th>
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
      {correctionNotes.map((note) => (
        <p key={note} className="ledger-meta" data-testid="overview-chart-correction">
          Correction note: {note}
        </p>
      ))}
    </div>
  );
}
