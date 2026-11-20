import { SEVERITY_META, SEVERITY_ORDER, formatInt, sharePercent } from "./chartTokens";

export function SeverityMix({
  bands,
  publishedTotal,
}: {
  bands: Record<string, number>;
  publishedTotal: number;
}) {
  return (
    <ul className="severity-list" data-testid="overview-severity-list">
      {SEVERITY_ORDER.map((band) => {
        const meta = SEVERITY_META[band];
        const count = bands[band] ?? 0;
        const share = sharePercent(count, publishedTotal);
        return (
          <li key={band}>
            <a
              className="severity-row"
              href={`/explore?severity=${band}`}
              data-testid={`overview-severity-${band}`}
              // No `title`: the row prints the count and the share, and the
              // accessible name carries both plus the action, so the native
              // tooltip was a second, slower copy of visible text. The one fact
              // it alone held (what the band is scored from) moved into the name.
              aria-label={`${meta.label}: ${formatInt(count)} published, ${share} of the corpus. ${meta.note}. Open in Explore.`}
            >
              <span className="severity-label">
                <span
                  className="severity-dot"
                  style={{ background: meta.color }}
                  aria-hidden="true"
                />
                {meta.label}
              </span>
              <span className="severity-track" aria-hidden="true">
                <span
                  className="severity-fill"
                  style={{
                    width: `${Math.max(count > 0 ? 0.6 : 0, (count / publishedTotal) * 100)}%`,
                    background: meta.color,
                  }}
                />
              </span>
              <span className="severity-value">
                <strong>{formatInt(count)}</strong>
                {share}
              </span>
            </a>
          </li>
        );
      })}
    </ul>
  );
}
