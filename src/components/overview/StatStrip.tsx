import { formatInt, sharePercent } from "@/components/charts/chartTokens";
import { HelpTip } from "@/components/ledger/HelpTip";
import type { CorpusStats } from "./loadOverview";

export function StatStrip({ corpus, kevLastMonth }: { corpus: CorpusStats; kevLastMonth: number }) {
  return (
    <div className="stat-grid" data-testid="overview-corpus">
      <div className="stat">
        <div className="stat-label">Unknown dates</div>
        <div className="stat-value" data-testid="overview-corpus-unknown-date">
          {formatInt(corpus.unknownDate)}
        </div>
        <div className="stat-note">excluded from dated charts, never zero</div>
      </div>
      <div className="stat">
        <div className="stat-label">
          <span className="status-dot" style={{ background: "var(--ui-ink)" }} aria-hidden="true" />
          KEV-listed
        </div>
        <div className="stat-value" data-testid="overview-corpus-kev">
          {formatInt(corpus.kev)}
        </div>
        <div className="stat-note">+{formatInt(kevLastMonth)} additions in the latest month</div>
      </div>
      <div className="stat">
        <div className="stat-label">
          <span
            className="status-dot"
            style={{ background: "var(--ui-accent)" }}
            aria-hidden="true"
          />
          EPSS-scored
        </div>
        <div className="stat-value" data-testid="overview-corpus-epss">
          {formatInt(corpus.epssScored)}
        </div>
        <div className="stat-note">
          {corpus.epssScoreDate !== null ? `score date ${corpus.epssScoreDate}` : "no score date"}
        </div>
      </div>
      <div className="stat">
        <div className="stat-label">
          <span className="status-dot is-stale" aria-hidden="true" />
          Unscored severity
        </div>
        <div className="stat-value" data-testid="overview-corpus-unscored">
          {formatInt(corpus.unscored)}
        </div>
        <div className="stat-note">
          {sharePercent(corpus.unscored, corpus.published)} of the corpus · not low
        </div>
        {/*
          The unscored cohort is split by what can still be read: an ADP
          secondary metric is context only, so the split is stated here and
          never turned into a band, a share of the corpus, or a filter.
        */}
        <div className="stat-note stat-subnote" data-testid="overview-corpus-unscored-split">
          <span data-testid="overview-corpus-secondary-only">
            {formatInt(corpus.secondaryOnly)}
          </span>{" "}
          with ADP secondary (context) ·{" "}
          <span data-testid="overview-corpus-no-metric">{formatInt(corpus.noMetric)}</span> with no
          published metric (of {formatInt(corpus.unscored)} unscored)
          <HelpTip term="the unscored severity split" testId="overview-corpus-unscored-split-help">
            An ADP metric is published by an Authorized Data Publisher, not by the CNA, so it is
            secondary: context only. It is never used for ranking, ordering, filtering, or
            eligibility, and it never becomes this record&apos;s primary severity. Records counted as
            having no published metric have neither a valid CNA metric nor a valid ADP metric; that
            is a data gap, not low severity. The two counts always add up to the unscored total;
            their denominator is the unscored cohort, not the whole corpus.
          </HelpTip>
        </div>
      </div>
    </div>
  );
}
