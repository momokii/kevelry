import { formatInt, monthShort } from "./chartTokens";

export function KevRhythm({
  months,
  total,
}: {
  months: Array<{ month: string; count: number }>;
  total: number;
}) {
  const max = Math.max(1, ...months.map((entry) => entry.count));
  return (
    <div data-testid="overview-kev-chart">
      <div className="kev-bars" role="img" aria-label="KEV catalog additions by UTC month">
        {months.map((entry) => (
          <div
            key={entry.month}
            className="kev-bar"
            title={`${monthShort(entry.month)}: ${formatInt(entry.count)} KEV additions`}
          >
            <span
              className="kev-bar-fill"
              style={{ height: `${6 + (entry.count / max) * 78}px` }}
              aria-hidden="true"
            />
            <span className="kev-bar-label" aria-hidden="true">
              {monthShort(entry.month)}
            </span>
          </div>
        ))}
      </div>
      <p className="chart-note">
        <strong>{formatInt(total)}</strong> catalog additions in twelve months. This is
        catalog activity, not exploitation volume: a quiet month means no new listings.
      </p>
    </div>
  );
}
