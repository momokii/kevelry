import { CorpusStats } from "@/components/overview/CorpusStats";
import { ForecastChart } from "@/components/overview/ForecastChart";
import { KevChart } from "@/components/overview/KevChart";
import { OverviewSearch } from "@/components/overview/OverviewSearch";
import { PrioritySummaries } from "@/components/overview/PrioritySummaries";
import { PublicationChart } from "@/components/overview/PublicationChart";
import { SeverityChart } from "@/components/overview/SeverityChart";
import { SourceFreshness } from "@/components/overview/SourceFreshness";
import { loadOverviewData, resolveDataDir } from "@/components/overview/loadOverview";
import { Masthead } from "@/components/ledger/Masthead";
import { severityRows } from "@/components/overview/chartData";

export const revalidate = 60;

export const metadata = {
  title: "Overview — CVE Change Radar",
  description:
    "Published-CVE volume by UTC day, per-source freshness, and priority entry points from the retained local snapshot.",
};

export default function OverviewPage() {
  const data = loadOverviewData(resolveDataDir(), new Date().toISOString());
  if (data === null) {
    return (
      <main className="ledger-page" data-testid="overview-root" id="main-content">
        <Masthead current="Overview" testId="overview-masthead" />
        <h1>Overview</h1>
        <div className="ledger-section" data-testid="overview-unavailable">
          <h2>Local snapshot unavailable</h2>
          <p>
            The retained snapshot could not be read from the configured data directory. No data is
            shown rather than substituted data.
          </p>
        </div>
      </main>
    );
  }
  return (
    <main className="ledger-page" data-testid="overview-root" id="main-content">
      <Masthead current="Overview" testId="overview-masthead" />
      <h1>Overview</h1>
      <p className="ledger-meta" data-testid="overview-lede">
        Published CVE volume, source freshness, and priority entry points from the retained local
        snapshot. Date basis: publication timestamp in UTC calendar buckets.
      </p>

      <section className="ledger-section" aria-labelledby="overview-corpus-heading">
        <h2 id="overview-corpus-heading">Corpus at a glance</h2>
        <CorpusStats corpus={data.corpus} generatedAt={data.generatedAt} />
      </section>

      <section className="ledger-section" aria-labelledby="overview-search-heading">
        <h2 id="overview-search-heading">Search the snapshot</h2>
        <OverviewSearch />
      </section>

      <section className="ledger-section" aria-labelledby="overview-chart-heading">
        <h2 id="overview-chart-heading">Publication volume</h2>
        {data.empty ? (
          <PublicationChart
            days={[]}
            total30={0}
            publishedTotal={0}
            anchorDay={null}
            unknownDateCount={0}
            correctionNotes={[]}
          />
        ) : (
          <PublicationChart
            days={data.volume30}
            total30={data.volumeTotal30}
            publishedTotal={data.publishedTotal}
            anchorDay={data.anchorDay}
            unknownDateCount={data.unknownDateCount}
            correctionNotes={data.correctionNotes}
          />
        )}
      </section>

      <section className="ledger-section" aria-labelledby="overview-severity-heading">
        <h2 id="overview-severity-heading">Severity mix</h2>
        <SeverityChart
          rows={severityRows(data.severityBands)}
          publishedTotal={data.publishedTotal}
        />
      </section>

      <section className="ledger-section" aria-labelledby="overview-forecast-heading">
        <h2 id="overview-forecast-heading">Forecast distribution</h2>
        <ForecastChart
          histogram={data.epssHistogram}
          publishedTotal={data.publishedTotal}
          epssScoreDate={data.epssScoreDate}
        />
      </section>

      <section className="ledger-section" aria-labelledby="overview-kev-heading">
        <h2 id="overview-kev-heading">Known-exploited additions</h2>
        <KevChart months={data.kevByMonth} />
      </section>

      <section className="ledger-section" aria-labelledby="overview-freshness-heading">
        <h2 id="overview-freshness-heading">Source freshness</h2>
        <SourceFreshness provenance={data.provenance} />
      </section>

      <section className="ledger-section" aria-labelledby="overview-priority-heading">
        <h2 id="overview-priority-heading">Priority lists</h2>
        <PrioritySummaries summaries={data.summaries} empty={data.empty} />
      </section>

      <section className="ledger-section" aria-labelledby="overview-method-heading">
        <h2 id="overview-method-heading">How to read this page</h2>
        <p className="ledger-meta" data-testid="overview-method-note">
          Every count, signal, and freshness label comes from the accepted local snapshot; nothing
          is estimated. See the <a href="/methodology">methodology and data-status page</a> for
          ordering rules, coverage gaps, and reuse notices.
        </p>
      </section>
    </main>
  );
}
