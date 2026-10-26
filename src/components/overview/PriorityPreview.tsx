import type { PrioritySummary } from "./loadOverview";

export function PriorityPreview({
  summaries,
  empty,
}: {
  summaries: PrioritySummary[];
  empty: boolean;
}) {
  return (
    <div data-testid="overview-priority">
      {empty ? (
        <p className="empty-state" data-testid="overview-priority-empty">
          <strong>No priority lists yet</strong>
          The retained snapshot holds no published records, so every list is empty.
        </p>
      ) : null}
      <div className="priority-grid">
        {summaries.map((summary) => (
          <section key={summary.key} className="priority-block">
            <div className="priority-block-head">
              <h3>{summary.title}</h3>
              <a
                className="link-arrow"
                href={summary.href}
                data-testid={`overview-priority-${summary.key}-more`}
              >
                Full list
              </a>
            </div>
            <p className="chart-note" data-testid={`overview-priority-${summary.key}-ordering`}>
              {summary.ordering}
            </p>
            {summary.items.length === 0 ? (
              <p className="chart-note" data-testid={`overview-priority-${summary.key}-empty`}>
                {summary.emptyNote}
              </p>
            ) : (
              <div className="priority-mini" data-testid={`overview-priority-${summary.key}-list`}>
                {summary.items.map((item, index) => (
                  <a key={item.cveId} className="priority-mini-row" href={item.officialUrl}>
                    <span className="priority-mini-rank">{String(index + 1).padStart(2, "0")}</span>
                    <span className="priority-mini-body">
                      <span className="mono" style={{ fontSize: 11 }}>
                        {item.cveId}
                      </span>
                      <span className="priority-mini-title">{item.title}</span>
                      <span className="priority-mini-signals">
                        <span className="chart-note" style={{ margin: 0 }}>
                          {item.signal}
                        </span>
                      </span>
                    </span>
                  </a>
                ))}
              </div>
            )}
          </section>
        ))}
      </div>
    </div>
  );
}
