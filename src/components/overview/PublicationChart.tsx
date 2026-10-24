import type { DayBucket } from "./loadOverview";

type PublicationChartProps = {
  buckets: DayBucket[];
  anchorDay: string | null;
  unknownDateCount: number;
  correctionNotes: string[];
};

const MAX_BAR_HEIGHT = 96;
const MIN_BAR_HEIGHT = 8;

export function PublicationChart({
  buckets,
  anchorDay,
  unknownDateCount,
  correctionNotes,
}: PublicationChartProps) {
  if (buckets.length === 0) {
    return (
      <div className="ledger-skeleton" data-testid="overview-chart-empty">
        Empty interval: no published records in the retained snapshot. This is an honest empty
        state, not a zero baseline.
      </div>
    );
  }
  const peak = buckets.reduce((max, bucket) => Math.max(max, bucket.count), 0);
  const heightFor = (count: number): number => {
    if (peak <= 0) return MIN_BAR_HEIGHT;
    return Math.round(MIN_BAR_HEIGHT + (count / peak) * (MAX_BAR_HEIGHT - MIN_BAR_HEIGHT));
  };
  return (
    <div data-testid="overview-chart">
      <div className="ledger-chart-bars" aria-hidden="true" data-testid="overview-chart-bars">
        {buckets.map((bucket) => (
          <div
            key={bucket.bucketStart}
            className="ledger-chart-bar"
            style={{ height: `${heightFor(bucket.count)}px` }}
          />
        ))}
        <div
          className="ledger-chart-bar ledger-chart-bar-secondary"
          style={{ height: `${heightFor(unknownDateCount)}px` }}
          data-testid="overview-chart-unknown-bar"
        />
      </div>
      <table className="ledger-chart-table" data-testid="overview-chart-table">
        <caption className="ledger-meta" data-testid="overview-chart-caption">
          {anchorDay === null
            ? "Publication counts by UTC calendar day."
            : `Publication counts by UTC calendar day for the 14 days ending ${anchorDay}. Unknown dates are excluded from dated bars.`}
        </caption>
        <thead>
          <tr>
            <th scope="col">UTC bucket</th>
            <th scope="col">Records</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((bucket) => (
            <tr key={bucket.bucketStart}>
              <th scope="row">{bucket.bucketStart}</th>
              <td data-testid={`overview-chart-count-${bucket.bucketStart}`}>
                {bucket.count === 0 ? "0 in this interval" : `${bucket.count} published`}
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
