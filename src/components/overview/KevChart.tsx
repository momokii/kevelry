import { ChartBars, type BarDatum } from "./ChartBars";
import { KEV_VIEW_HREF, formatCount, monthLabel } from "./chartData";
import type { KevMonthBucket } from "./loadOverview";

type KevChartProps = {
  months: KevMonthBucket[];
};

export function KevChart({ months }: KevChartProps) {
  const items: BarDatum[] = months.map((entry) => ({
    key: entry.month,
    label: monthLabel(entry.month) ?? entry.month,
    count: entry.count,
    href: KEV_VIEW_HREF,
  }));
  const added = months.reduce((sum, entry) => sum + entry.count, 0);
  return (
    <div data-testid="overview-kev">
      <p className="ledger-meta" data-testid="overview-kev-summary">
        <span className="ledger-emphasis">{formatCount(added)} KEV additions in 12 months</span>.{" "}
        <span className="ledger-caveat">
          This is catalog additions by date added, not exploitation volume: one entry per CVE, and a
          quiet month means no new listings, not no attacks.
        </span>
      </p>
      <ChartBars
        testId="overview-kev-months"
        ariaLabel="KEV catalog additions by month, last 12 months. Horizontal scroll region."
        items={items}
        denominator={added}
        denominatorNoun="KEV additions in this window"
        basis="KEV basis: catalog date added per retained KEV entry, grouped by UTC month."
        actionLabel="Activate to open the known-exploited list"
        emptyMessage="No KEV entries with a parseable date added in the retained snapshot."
      />
    </div>
  );
}
