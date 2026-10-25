import { ChartBars, type BarDatum } from "./ChartBars";
import { FORECAST_VIEW_HREF, epssBucketLabel, formatCount } from "./chartData";

type ForecastChartProps = {
  histogram: number[];
  publishedTotal: number;
  epssScoreDate: string | null;
};

export function ForecastChart({ histogram, publishedTotal, epssScoreDate }: ForecastChartProps) {
  const buckets = histogram.slice(0, 10);
  while (buckets.length < 10) buckets.push(0);
  const scored = buckets.reduce((sum, count) => sum + count, 0);
  const items: BarDatum[] = buckets.map((count, index) => ({
    key: `epss-${index}`,
    label: epssBucketLabel(index) ?? `bucket ${index}`,
    count,
    href: FORECAST_VIEW_HREF,
  }));
  const basis =
    epssScoreDate === null
      ? "EPSS basis: no accepted score date in the retained snapshot, so every bucket reads 0 in this interval."
      : `EPSS basis: dated forecast for score date ${epssScoreDate}; probabilities expire and are never current severity.`;
  return (
    <div data-testid="overview-forecast">
      <p className="ledger-meta" data-testid="overview-forecast-summary">
        <span className="ledger-emphasis">{formatCount(scored)} scored forecasts</span> of{" "}
        {formatCount(publishedTotal)} published.{" "}
        <span className="ledger-caveat">
          EPSS is a dated exploitation forecast, not a severity rating; bars link to the highest
          forecast list because Explore cannot filter by probability range.
        </span>
      </p>
      <ChartBars
        testId="overview-forecast-epss"
        ariaLabel="EPSS forecast distribution in ten probability buckets. Horizontal scroll region."
        items={items}
        denominator={scored}
        denominatorNoun="scored forecasts"
        basis={basis}
        actionLabel="Activate to open the highest-forecast list"
        emptyMessage="No EPSS score date accepted in the retained snapshot."
      />
    </div>
  );
}
