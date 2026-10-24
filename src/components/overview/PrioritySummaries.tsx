import type { PrioritySummary } from "./loadOverview";

type PrioritySummariesProps = {
  summaries: PrioritySummary[];
  empty: boolean;
};

export function PrioritySummaries({ summaries, empty }: PrioritySummariesProps) {
  return (
    <div data-testid="overview-priority">
      {empty ? (
        <p className="ledger-meta" data-testid="overview-priority-empty">
          No priority lists yet: the retained snapshot holds no published records, so every list is
          empty.
        </p>
      ) : null}
      {summaries.map((summary) => (
        <section key={summary.key} aria-labelledby={`overview-priority-${summary.key}-heading`}>
          <h3 id={`overview-priority-${summary.key}-heading`}>{summary.title}</h3>
          <p className="ledger-meta" data-testid={`overview-priority-${summary.key}-ordering`}>
            Ordering: {summary.ordering}
          </p>
          {summary.items.length === 0 ? (
            <p className="ledger-meta" data-testid={`overview-priority-${summary.key}-empty`}>
              {summary.emptyNote}
            </p>
          ) : (
            <div data-testid={`overview-priority-${summary.key}-list`}>
              {summary.items.map((item) => (
                <article key={item.cveId} className="ledger-row">
                  <span className="ledger-row-id">{item.cveId}</span>
                  <p className="ledger-row-title">{item.title}</p>
                  <p className="ledger-row-signals">{item.signal}</p>
                  <a className="ledger-row-action" href={item.officialUrl}>
                    Official CVE record
                  </a>
                </article>
              ))}
            </div>
          )}
          <p>
            <a
              className="ledger-more-link"
              href={summary.href}
              data-testid={`overview-priority-${summary.key}-more`}
            >
              Full {summary.title.toLowerCase()} list
            </a>
          </p>
        </section>
      ))}
    </div>
  );
}
