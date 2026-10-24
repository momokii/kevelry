import { CompareField } from "@/components/ledger/CompareField";
import { CveResultRow } from "@/components/ledger/CveResultRow";
import { ChartView } from "@/components/ledger/ChartView";
import { EvidenceStrip } from "@/components/ledger/EvidenceStrip";
import { FilterGroup } from "@/components/ledger/FilterGroup";
import { Masthead } from "@/components/ledger/Masthead";
import { OrderingExplanation } from "@/components/ledger/OrderingExplanation";
import { SearchField } from "@/components/ledger/SearchField";
import { SnapshotSelector } from "@/components/ledger/SnapshotSelector";
import { UpdateNotice } from "@/components/ledger/UpdateNotice";
import type { ReactNode } from "react";

export const metadata = {
  title: "Evidence Ledger primitive showcase",
  description: "Every Section-6 primitive in every required state. No product screens, no data logic.",
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
    <main className="ledger-page" data-testid="showcase-root">
      <h1>Evidence Ledger primitive showcase</h1>
      <p className="ledger-meta">
        Every Section-6 primitive in each required state. Tokens: DESIGN.md sections 2-4. Copy guardrails: DESIGN.md
        section 8. No product screens, no data fetching.
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
            <FilterGroup selected={["Known exploited", "Rising forecast"]} testId="filter-selected" />
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
