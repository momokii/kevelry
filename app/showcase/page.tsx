import { CompareField } from "@/components/ledger/CompareField";
import { CveResultRow } from "@/components/ledger/CveResultRow";
import { ChartView } from "@/components/ledger/ChartView";
import { EvidenceStrip } from "@/components/ledger/EvidenceStrip";
import { FilterGroup } from "@/components/ledger/FilterGroup";
import { HelpTip } from "@/components/ledger/HelpTip";
import { Masthead } from "@/components/ledger/Masthead";
import { OrderingExplanation } from "@/components/ledger/OrderingExplanation";
import { SearchField } from "@/components/ledger/SearchField";
import { SnapshotSelector } from "@/components/ledger/SnapshotSelector";
import { TimeText } from "@/components/ledger/TimeText";
import { TimeZoneSelect } from "@/components/ledger/TimeZoneSelect";
import { UpdateNotice } from "@/components/ledger/UpdateNotice";
import type { ReactNode } from "react";

const DEMO_INSTANT = "2026-10-25T05:14:00.000Z";
const DEMO_NOW = Date.parse(DEMO_INSTANT) + (2 * 60 + 14) * 60 * 1000;

export const metadata = {
  title: "Research Console primitive showcase",
  description:
    "Every Section-6 primitive in every required state. No product screens, no data logic.",
};

function StateCard({ id, label, children }: { id: string; label: string; children: ReactNode }) {
  return (
    <div className="ledger-state-card" data-testid={id}>
      <span className="ledger-state-label">{label}</span>
      {children}
    </div>
  );
}

export default function ShowcasePage() {
  return (
    <main className="ledger-page" data-testid="showcase-root" id="main-content">
      <h1>Research Console primitive showcase</h1>
      <p className="ledger-meta">
        Every Section-6 primitive in each required state. Tokens: DESIGN.md sections 2-4. Copy
        guardrails: DESIGN.md section 8. No product screens, no data fetching.
      </p>

      <section className="ledger-section" aria-labelledby="section-masthead" id="section-masthead">
        <h2 id="section-masthead-heading">Masthead and navigation</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-masthead-default" label="default">
            <Masthead testId="masthead-default" />
          </StateCard>
          <StateCard id="state-masthead-current" label="current page">
            <Masthead current="Priority" testId="masthead-current" />
          </StateCard>
          <StateCard id="state-masthead-focus" label="focus-visible (tab to nav links)">
            <Masthead testId="masthead-focus" />
          </StateCard>
          <StateCard id="state-masthead-wrapped" label="wrapped mobile menu">
            <Masthead menuOpen testId="masthead-wrapped" />
          </StateCard>
          <StateCard id="state-masthead-historical" label="historical context">
            <Masthead historical testId="masthead-historical" />
          </StateCard>
          <StateCard id="state-masthead-hover" label="hover (hover a nav link)">
            <Masthead testId="masthead-hover" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-search">
        <h2 id="section-search">Search field and action</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-search-default" label="default / empty">
            <SearchField state="default" testId="search-default" />
          </StateCard>
          <StateCard id="state-search-populated" label="populated">
            <SearchField state="populated" testId="search-populated" />
          </StateCard>
          <StateCard id="state-search-focus" label="focus-visible (input)">
            <SearchField state="default" testId="search-focus" />
          </StateCard>
          <StateCard id="state-search-hover" label="hover (hover the action)">
            <SearchField state="populated" testId="search-hover" />
          </StateCard>
          <StateCard id="state-search-pending" label="pending / loading">
            <SearchField state="pending" testId="search-pending" />
          </StateCard>
          <StateCard id="state-search-invalid" label="invalid query / error">
            <SearchField state="invalid" query="**" testId="search-invalid" />
          </StateCard>
          <StateCard id="state-search-empty" label="no matches / empty">
            <SearchField state="empty" query="no-such-record-here" testId="search-empty" />
          </StateCard>
          <StateCard id="state-search-error" label="error">
            <SearchField state="error" testId="search-error" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-filters">
        <h2 id="section-filters">Filter control and group</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-filter-default" label="default">
            <FilterGroup testId="filter-default" />
          </StateCard>
          <StateCard id="state-filter-selected" label="selected">
            <FilterGroup
              selected={["Known exploited", "Rising forecast"]}
              testId="filter-selected"
            />
          </StateCard>
          <StateCard id="state-filter-hover" label="hover (hover a chip)">
            <FilterGroup testId="filter-hover" />
          </StateCard>
          <StateCard id="state-filter-focus" label="focus-visible (tab to a chip)">
            <FilterGroup testId="filter-focus" />
          </StateCard>
          <StateCard id="state-filter-disabled" label="disabled">
            <FilterGroup disabled selected={["Known exploited"]} testId="filter-disabled" />
          </StateCard>
          <StateCard id="state-filter-empty" label="cleared / empty">
            <FilterGroup testId="filter-empty" />
          </StateCard>
          <StateCard id="state-filter-wrapped" label="wrapped labels">
            <FilterGroup wrapped testId="filter-wrapped" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-rows">
        <h2 id="section-rows">CVE result row</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-row-default" label="default">
            <CveResultRow variant="default" testId="row-default" />
          </StateCard>
          <StateCard id="state-row-hover" label="hover (hover the official-record link)">
            <CveResultRow variant="default" testId="row-hover" />
          </StateCard>
          <StateCard id="state-row-focus" label="focus-visible (tab to the action)">
            <CveResultRow variant="default" testId="row-focus" />
          </StateCard>
          <StateCard id="state-row-long" label="long text plus unbroken URL stress">
            <CveResultRow variant="long" testId="row-long" />
          </StateCard>
          <StateCard id="state-row-missing" label="missing description / empty">
            <CveResultRow variant="missing" testId="row-missing" />
          </StateCard>
          <StateCard id="state-row-unscored" label="unscored">
            <CveResultRow variant="unscored" testId="row-unscored" />
          </StateCard>
          <StateCard id="state-row-unknown" label="unknown EPSS">
            <CveResultRow variant="unknown-epss" testId="row-unknown" />
          </StateCard>
          <StateCard id="state-row-rejected" label="rejected transition">
            <CveResultRow variant="rejected" testId="row-rejected" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-evidence">
        <h2 id="section-evidence">Evidence strip</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-evidence-default" label="default">
            <EvidenceStrip state="default" testId="evidence-default" />
          </StateCard>
          <StateCard id="state-evidence-loading" label="loading">
            <EvidenceStrip state="loading" testId="evidence-loading" />
          </StateCard>
          <StateCard id="state-evidence-stale" label="stale">
            <EvidenceStrip state="stale" testId="evidence-stale" />
          </StateCard>
          <StateCard id="state-evidence-failed" label="failed / error">
            <EvidenceStrip state="failed" testId="evidence-failed" />
          </StateCard>
          <StateCard id="state-evidence-missing" label="missing / empty">
            <EvidenceStrip state="missing" testId="evidence-missing" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-chart">
        <h2 id="section-chart">Chart and accessible data view</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-chart-default" label="default">
            <ChartView state="default" testId="chart-default" />
          </StateCard>
          <StateCard id="state-chart-loading" label="loading">
            <ChartView state="loading" testId="chart-loading" />
          </StateCard>
          <StateCard id="state-chart-empty" label="empty interval / empty">
            <ChartView state="empty" testId="chart-empty" />
          </StateCard>
          <StateCard id="state-chart-unknown" label="unknown-date bucket">
            <ChartView state="unknown" testId="chart-unknown" />
          </StateCard>
          <StateCard id="state-chart-correction" label="correction note">
            <ChartView state="correction" testId="chart-correction" />
          </StateCard>
          <StateCard id="state-chart-keyboard" label="keyboard equivalent (focusable table)">
            <ChartView state="default" testId="chart-keyboard" />
          </StateCard>
          <StateCard id="state-chart-error" label="error">
            <ChartView state="error" testId="chart-error" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-ordering">
        <h2 id="section-ordering">List mode and ordering explanation</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-ordering-default" label="default / current policy">
            <OrderingExplanation state="default" testId="ordering-default" />
          </StateCard>
          <StateCard id="state-ordering-tie" label="tie explained">
            <OrderingExplanation state="tie" testId="ordering-tie" />
          </StateCard>
          <StateCard id="state-ordering-missing" label="missing values explained">
            <OrderingExplanation state="missing" testId="ordering-missing" />
          </StateCard>
          <StateCard id="state-ordering-coverage" label="coverage denominator">
            <OrderingExplanation state="coverage" testId="ordering-coverage" />
          </StateCard>
          <StateCard id="state-ordering-stale" label="stale policy / error">
            <OrderingExplanation state="stale" testId="ordering-stale" />
          </StateCard>
          <StateCard id="state-ordering-focus" label="focus-visible (tab to the note)">
            <OrderingExplanation state="default" testId="ordering-focus" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-compare">
        <h2 id="section-compare">Compare field</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-compare-unchanged" label="unchanged">
            <CompareField change="unchanged" testId="compare-unchanged" />
          </StateCard>
          <StateCard id="state-compare-added" label="added">
            <CompareField change="added" testId="compare-added" />
          </StateCard>
          <StateCard id="state-compare-removed" label="removed">
            <CompareField change="removed" testId="compare-removed" />
          </StateCard>
          <StateCard id="state-compare-changed" label="changed">
            <CompareField change="changed" testId="compare-changed" />
          </StateCard>
          <StateCard id="state-compare-unknown" label="unknown / empty">
            <CompareField change="unknown" testId="compare-unknown" />
          </StateCard>
          <StateCard id="state-compare-incomparable" label="incomparable / error">
            <CompareField change="incomparable" testId="compare-incomparable" />
          </StateCard>
          <StateCard id="state-compare-focus" label="focus-visible (selectable values)">
            <CompareField change="changed" testId="compare-focus" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-snapshot">
        <h2 id="section-snapshot">Snapshot selector</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-snapshot-default" label="default / available">
            <SnapshotSelector state="available" testId="snapshot-default" />
          </StateCard>
          <StateCard id="state-snapshot-focus" label="focus-visible (tab to the select)">
            <SnapshotSelector state="available" testId="snapshot-focus" />
          </StateCard>
          <StateCard id="state-snapshot-loading" label="loading">
            <SnapshotSelector state="loading" testId="snapshot-loading" />
          </StateCard>
          <StateCard id="state-snapshot-missing" label="missing / empty">
            <SnapshotSelector state="missing" testId="snapshot-missing" />
          </StateCard>
          <StateCard id="state-snapshot-expired" label="expired / error">
            <SnapshotSelector state="expired" testId="snapshot-expired" />
          </StateCard>
          <StateCard id="state-snapshot-initial" label="initial, no history / empty">
            <SnapshotSelector state="initial" testId="snapshot-initial" />
          </StateCard>
          <StateCard id="state-snapshot-stale" label="stale historical source / error">
            <SnapshotSelector state="stale" testId="snapshot-stale" />
          </StateCard>
          <StateCard id="state-snapshot-disabled" label="disabled">
            <SnapshotSelector state="disabled" testId="snapshot-disabled" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-notice">
        <h2 id="section-notice">Update notice</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-notice-default" label="default">
            <UpdateNotice state="default" testId="notice-default" />
          </StateCard>
          <StateCard id="state-notice-pending" label="pending update">
            <UpdateNotice state="pending" testId="notice-pending" />
          </StateCard>
          <StateCard id="state-notice-applied" label="applied">
            <UpdateNotice state="applied" testId="notice-applied" />
          </StateCard>
          <StateCard id="state-notice-dismissed" label="dismissed / empty">
            <UpdateNotice state="dismissed" testId="notice-dismissed" />
          </StateCard>
          <StateCard id="state-notice-focus" label="focus-visible (tab to the action)">
            <UpdateNotice state="pending" testId="notice-focus" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-time" id="section-time">
        <h2 id="section-time">Display timezone and timestamp</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-time-live" label="live (follows the selector)">
            <TimeZoneSelect testId="timezone-select" />
            <p>
              Observed:{" "}
              <TimeText value={DEMO_INSTANT} showRelative now={DEMO_NOW} testId="timetext-live" />
            </p>
          </StateCard>
          <StateCard id="state-time-jakarta" label="Jakarta zone">
            <TimeText value={DEMO_INSTANT} timeZone="Asia/Jakarta" testId="timetext-jakarta" />
          </StateCard>
          <StateCard id="state-time-utc" label="UTC zone">
            <TimeText value={DEMO_INSTANT} timeZone="UTC" testId="timetext-utc" />
          </StateCard>
          <StateCard id="state-time-newyork" label="New York zone (daylight)">
            <TimeText value={DEMO_INSTANT} timeZone="America/New_York" testId="timetext-newyork" />
          </StateCard>
          <StateCard id="state-time-relative" label="relative form">
            <TimeText
              value={DEMO_INSTANT}
              timeZone="Asia/Jakarta"
              showRelative
              now={DEMO_NOW}
              testId="timetext-relative"
            />
          </StateCard>
          <StateCard id="state-time-dateonly" label="date-only input">
            <TimeText value="2026-10-24" timeZone="Asia/Jakarta" testId="timetext-dateonly" />
          </StateCard>
          <StateCard id="state-time-invalid" label="invalid input / empty">
            <TimeText value="not-a-date" timeZone="Asia/Jakarta" testId="timetext-invalid" />
          </StateCard>
          <StateCard id="state-time-missing" label="missing input / empty">
            <TimeText value={null} timeZone="Asia/Jakarta" testId="timetext-missing" />
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-helptip" id="section-helptip">
        <h2 id="section-helptip">Help tip disclosure</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-helptip-closed" label="closed">
            <p>
              EPSS is a daily forecast of exploitation probability.{" "}
              <HelpTip term="EPSS" testId="helptip-closed">
                Values run 0 to 1 with a model version and score date; unknown renders as an
                explicit null.
              </HelpTip>
            </p>
          </StateCard>
          <StateCard id="state-helptip-open" label="open (pinned)">
            <p>
              KEV membership means confirmed exploitation is cataloged.{" "}
              <HelpTip term="KEV" testId="helptip-open" defaultOpen>
                The catalog date is shown beside each member; absence from the list is never proof
                of safety.
              </HelpTip>
            </p>
          </StateCard>
          <StateCard id="state-helptip-focus" label="focus-visible (tab to the trigger)">
            <p>
              CVSS severity here is CNA-supplied only.{" "}
              <HelpTip term="CVSS" testId="helptip-focus">
                Records without a CNA metric read as unscored even when another party publishes a
                score.
              </HelpTip>
            </p>
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-emphasis" id="section-emphasis">
        <h2 id="section-emphasis">Typographic emphasis</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-emphasis-value" label="key value">
            <p data-testid="emphasis-emphasis">
              Known exploited: <span className="ledger-emphasis">CVE-2026-1234</span> was added to
              the catalog.
            </p>
          </StateCard>
          <StateCard id="state-emphasis-caveat" label="caveat">
            <p data-testid="emphasis-caveat">
              Forecast <span className="ledger-emphasis">0.82</span>{" "}
              <span className="ledger-caveat">
                model v4 dated 2026-10-24; a forecast, not observed exploitation
              </span>
              .
            </p>
          </StateCard>
          <StateCard id="state-emphasis-label" label="signal name">
            <p data-testid="emphasis-label">
              <span className="ledger-label">EPSS</span>{" "}
              <span className="ledger-emphasis">0.82</span>{" "}
              <span className="ledger-caveat">forecast, not observed exploitation</span>
            </p>
          </StateCard>
        </div>
      </section>

      <section className="ledger-section" aria-labelledby="section-stress">
        <h2 id="section-stress">Content stress cases</h2>
        <div className="ledger-state-grid">
          <StateCard id="state-stress-empty" label="empty filter label set">
            <FilterGroup testId="stress-empty" />
          </StateCard>
          <StateCard id="state-stress-label" label="40-character vendor label">
            <FilterGroup
              wrapped
              selected={["Vendor label with a forty-character demonstration string"]}
              testId="stress-label"
            />
          </StateCard>
          <StateCard id="state-stress-url" label="unbroken URL in a result row">
            <CveResultRow variant="long" testId="stress-url" />
          </StateCard>
          <StateCard id="state-stress-zoom" label="200 percent zoom reflow target">
            <CveResultRow variant="default" testId="stress-zoom" />
          </StateCard>
        </div>
      </section>
    </main>
  );
}
