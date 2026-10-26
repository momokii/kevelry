import { formatInt, sharePercent } from "@/components/charts/chartTokens";
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
      </div>
    </div>
  );
}
