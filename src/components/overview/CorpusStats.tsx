import { TimeText } from "@/components/ledger/TimeText";

import { FORECAST_VIEW_HREF, formatCount, KEV_VIEW_HREF } from "./chartData";
import styles from "./charts.module.css";
import type { CorpusStats } from "./loadOverview";

type CorpusStatsProps = {
  corpus: CorpusStats;
  generatedAt: string;
};

export function CorpusStats({ corpus, generatedAt }: CorpusStatsProps) {
  return (
    <div data-testid="overview-corpus">
      <ul className={styles.statStrip} data-testid="overview-corpus-stats">
        <li className={styles.statItem} data-testid="overview-corpus-published">
          <span className="ledger-label">Published</span>{" "}
          <a href="/explore" className="ledger-emphasis">
            {formatCount(corpus.published)}
          </a>
        </li>
        <li className={styles.statItem} data-testid="overview-corpus-kev">
          <span className="ledger-label">KEV-listed</span>{" "}
          <a href={KEV_VIEW_HREF} className="ledger-emphasis">
            {formatCount(corpus.kev)}
          </a>
        </li>
        <li className={styles.statItem} data-testid="overview-corpus-epss">
          <span className="ledger-label">EPSS-scored</span>{" "}
          <a href={FORECAST_VIEW_HREF} className="ledger-emphasis">
            {formatCount(corpus.epssScored)}
          </a>
        </li>
        <li className={styles.statItem} data-testid="overview-corpus-unscored">
          <span className="ledger-label">Unscored</span>{" "}
          <a href="/explore?severity=unknown" className="ledger-emphasis">
            {formatCount(corpus.unscored)}
          </a>
        </li>
        <li className={styles.statItem} data-testid="overview-corpus-unknown-date">
          <span className="ledger-label">Unknown dates</span>{" "}
          <span className="ledger-emphasis">{formatCount(corpus.unknownDate)}</span>{" "}
          <span className="ledger-caveat">
            (no date filter expresses this; see the volume table)
          </span>
        </li>
        <li className={styles.statItem} data-testid="overview-corpus-computed">
          <span className="ledger-label">Cache computed</span>{" "}
          {corpus.computedAt === null ? (
            <span className="ledger-caveat">live fallback: no aggregate cache yet</span>
          ) : (
            <TimeText
              value={corpus.computedAt}
              showRelative
              testId="overview-corpus-computed-time"
            />
          )}
        </li>
      </ul>
      <p className="ledger-meta" data-testid="overview-corpus-generated">
        Page generated{" "}
        <TimeText value={generatedAt} showRelative testId="overview-corpus-generated-time" />.
        Counts come from the accepted local snapshot; nothing is estimated.
      </p>
    </div>
  );
}
