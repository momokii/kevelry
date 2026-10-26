import { DensityMatrix } from "@/components/charts/DensityMatrix";
import { EpssDistribution } from "@/components/charts/EpssDistribution";
import { KevRhythm } from "@/components/charts/KevRhythm";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { CumulativeChart } from "@/components/charts/CumulativeChart";
import { VolumeChart } from "@/components/charts/VolumeChart";
import { ChartInfo } from "@/components/charts/ChartInfo";
import { formatInt, monthLong, sharePercent } from "@/components/charts/chartTokens";
import { TimeText } from "@/components/ledger/TimeText";
import { loadOverviewData, resolveDataDir } from "@/components/overview/loadOverview";
import { FreshnessPanel } from "@/components/overview/FreshnessPanel";
import { PriorityPreview } from "@/components/overview/PriorityPreview";
import { StatStrip } from "@/components/overview/StatStrip";
import { PageHeader } from "@/components/shell/PageHeader";
import { Panel } from "@/components/shell/Panel";

export const revalidate = 60;

export const metadata = {
  title: "Overview — CVE Intel",
  description:
    "Published CVE volume, severity composition, EPSS distribution, KEV rhythm, and source freshness from the retained snapshot.",
};

export default function OverviewPage() {
  const data = loadOverviewData(resolveDataDir(), new Date().toISOString());
  if (data === null) {
    return (
      <main className="page" data-testid="overview-root" id="main-content">
        <PageHeader
          eyebrow="Overview / all sources"
          title="The CVE landscape"
          lede="A retained, local snapshot. Nothing is estimated."
        />
        <div className="notice" data-testid="overview-unavailable">
          <span>
            <strong>Local snapshot unavailable.</strong> The retained snapshot could not be read
            from the configured data directory. No data is shown rather than substituted data.
          </span>
        </div>
      </main>
    );
  }

  const months = data.volumeMonths.map((bucket) => ({
    month: bucket.bucketStart,
    count: bucket.count,
  }));
  const firstMonth = months[0];
  const lastMonth = months[months.length - 1];
  const growth =
    firstMonth !== undefined && lastMonth !== undefined && firstMonth.count > 0
      ? (lastMonth.count / firstMonth.count).toFixed(1)
      : null;
  const lastMonthCount = lastMonth?.count ?? 0;
  const kevLastMonth = data.kevByMonth[data.kevByMonth.length - 1]?.count ?? 0;
  const latestLabel = lastMonth !== undefined ? monthLong(lastMonth.month) : null;
  const epssTotal = data.corpus.epssScored;

  return (
    <main className="page" data-testid="overview-root" id="main-content">
      <PageHeader
        eyebrow={
          <>
            <span>Overview</span>
            <span className="dot" aria-hidden="true" />
            <span>Retained snapshot</span>
            <span className="dot" aria-hidden="true" />
            <TimeText value={data.generatedAt} testId="overview-generated" />
          </>
        }
        title="What is changing in the CVE corpus?"
        lede="Volume, severity, and exploitation evidence from the retained local snapshot. Each number keeps its date basis; missing values stay unknown."
        actions={
          <>
            <a className="btn btn-sm" href="/methodology#methodology-section-status">
              Data status
            </a>
            <a className="btn btn-primary btn-sm" href="/explore">
              Explore records
            </a>
          </>
        }
      />

      <section className="hero-band" aria-labelledby="overview-hero-heading">
        <div className="hero-copy">
          <div className="eyebrow">Published CVE records</div>
          <div className="display" data-testid="overview-published-total">
            {formatInt(data.publishedTotal)}
          </div>
          <p className="hero-statement" id="overview-hero-heading">
            {growth !== null ? (
              <>
                Monthly publication is <strong>{growth}×</strong> the late-2024 level.{" "}
              </>
            ) : null}
            <strong>{formatInt(data.corpus.kev)}</strong> records carry confirmed-exploitation
            evidence; <strong>{formatInt(data.corpus.unscored)}</strong> have no primary severity
            score.
          </p>
          <p className="chart-note">
            Latest month: {latestLabel ?? "not recorded"} · {formatInt(lastMonthCount)} published ·
            no estimates where the source is silent.
          </p>
        </div>
        <div className="hero-aside">
          <div className="hero-mini">
            <span className="eyebrow">KEV edge</span>
            <strong>{sharePercent(data.corpus.kev, data.publishedTotal)}</strong>
            <span className="muted">of published records are in the accepted KEV snapshot.</span>
          </div>
          <div className="hero-mini">
            <span className="eyebrow">Forecast coverage</span>
            <strong>{sharePercent(epssTotal, data.publishedTotal)}</strong>
            <span className="muted">
              carry a current EPSS score
              {data.epssScoreDate !== null ? ` dated ${data.epssScoreDate}` : ""}.
            </span>
          </div>
        </div>
      </section>

      <StatStrip corpus={data.corpus} kevLastMonth={kevLastMonth} />

      <div className="grid" style={{ marginTop: "var(--ui-sp-6)" }}>
        <div className="stack span-8">
          <Panel
            title="Publication volume"
            sub="Monthly CVE publications in the retained snapshot. Select a month to inspect it; the chart window switches without changing the corpus."
            testId="overview-chart"
            actions={
              <ChartInfo>
                Bars are UTC calendar months, not smoothed. Select a bar with click or Enter, clear
                with Escape. The peak is marked. The y-axis is count; the x-axis is month. Unknown
                publication dates are excluded from this chart, not plotted as zero.
              </ChartInfo>
            }
          >
            <VolumeChart
              months={months}
              publishedTotal={data.publishedTotal}
              kevMonths={data.kevByMonth}
            />
          </Panel>
          <Panel
            title="Cumulative growth"
            sub="The running total inside this window. It is cumulative, not a forecast."
            testId="overview-cumulative-panel"
          >
            <CumulativeChart months={months} publishedTotal={data.publishedTotal} />
          </Panel>
        </div>

        <div className="stack span-4">
          <Panel
            title="Severity composition"
            sub="Primary CNA CVSS only. Click a band to filter Explore; unscored is an explicit band, never low."
            testId="overview-severity"
            actions={
              <ChartInfo>
                Bands follow the primary CNA metric, preferring v4.0 → v3.1 → v3.0. Legacy v2 is
                separate. ADP-only and metric-less records land in Unscored. Shares use all
                published records as the denominator.
              </ChartInfo>
            }
          >
            <SeverityDonut bands={data.severityBands} total={data.publishedTotal} />
          </Panel>

          <Panel
            title="EPSS distribution"
            sub="Log-spaced probability buckets reveal the base rate: most records sit far below 10%."
            testId="overview-forecast"
            actions={
              <ChartInfo>
                EPSS is a dated forecast of exploitation in the next 30 days, not severity. Bars use
                a log count scale so the tail is visible. Probability and percentile are different;
                this chart uses probability.
              </ChartInfo>
            }
          >
            <EpssDistribution
              histogram={data.epssLogHistogram}
              total={epssTotal}
              scoreDate={data.epssScoreDate}
            />
          </Panel>
        </div>

        <Panel
          title="Joint distribution: severity × forecast"
          sub="Every cell is an exact count from the accepted snapshot. Selection updates the inspector; arrow keys move between cells."
          className="span-12"
          testId="overview-density-panel"
          actions={
            <ChartInfo>
              CVSS rows are the primary CNA band. EPSS columns are log-spaced probability buckets.
              Cell darkness uses a square-root count scale; the ring marks cells with at least one
              KEV-listed CVE. No composite score is computed.
            </ChartInfo>
          }
        >
          <DensityMatrix
            cells={data.severityEpssMatrix}
            publishedTotal={data.publishedTotal}
            epssScored={epssTotal}
          />
        </Panel>

        <Panel
          title="KEV rhythm"
          sub="Catalog additions by month. This is listing activity, not exploitation volume."
          className="span-4"
          testId="overview-kev"
        >
          <KevRhythm
            months={data.kevByMonth}
            total={data.kevByMonth.reduce((sum, entry) => sum + entry.count, 0)}
          />
        </Panel>

        <Panel
          title="Source freshness"
          sub="How old the snapshot is, and what each state means for the numbers."
          className="span-4"
          testId="overview-freshness-panel"
        >
          <FreshnessPanel provenance={data.provenance} />
        </Panel>

        <Panel
          title="How this page stays honest"
          sub="No score stitching, no silent zeros, no interpolation."
          className="span-4"
          testId="overview-method-panel"
        >
          <ul className="plain-list">
            <li>
              <strong>Unknown stays unknown.</strong> Missing EPSS is not zero; missing CVSS is
              Unscored, not low.
            </li>
            <li>
              <strong>Three signals, never one score.</strong> KEV is evidence, EPSS is a dated
              forecast, CVSS is supplied severity.
            </li>
            <li>
              <strong>Every share names its denominator.</strong> Charts and tables use the same
              accepted snapshot.
            </li>
          </ul>
          <p className="chart-note" data-testid="overview-method-note">
            Read the <a href="/methodology">methodology and data status</a> for ordering rules,
            coverage gaps, and reuse notices.
          </p>
        </Panel>
      </div>

      <section className="section" style={{ marginTop: "var(--ui-sp-8)" }}>
        <div className="section-head">
          <div>
            <h2>Priority evidence</h2>
            <p className="takeaway">
              Four deterministic views. Each shows the signal that put a record there; none invents
              a composite score.
            </p>
          </div>
          <a className="btn btn-sm" href="/priority">
            Open priority workspace
          </a>
        </div>
        <PriorityPreview summaries={data.summaries} empty={data.empty} />
      </section>
    </main>
  );
}
