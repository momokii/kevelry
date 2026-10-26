import { formatInt, sharePercent } from "@/components/charts/chartTokens";

export function CoverageDiagram({
  published,
  cnaScored,
  epssScored,
  kev,
}: {
  published: number;
  cnaScored: number;
  epssScored: number;
  kev: number;
}) {
  const rows = [
    {
      label: "Published records",
      count: published,
      note: "the full accepted PUBLISHED cohort",
      tone: "ink",
    },
    {
      label: "Primary CNA CVSS",
      count: cnaScored,
      note: "has a usable primary CNA metric",
      tone: "critical",
    },
    {
      label: "Current EPSS",
      count: epssScored,
      note: "has a dated forecast for the accepted score date",
      tone: "accent",
    },
    {
      label: "KEV-listed",
      count: kev,
      note: "confirmed exploitation evidence, not a forecast",
      tone: "ink",
    },
  ];
  return (
    <div className="coverage-diagram" data-testid="methodology-coverage-diagram">
      {rows.map((row) => (
        <div className="coverage-row" key={row.label}>
          <span className="coverage-label">{row.label}</span>
          <span className="coverage-track" aria-hidden="true">
            <span
              className={`coverage-fill coverage-${row.tone}`}
              style={{
                width: `${Math.max(row.count > 0 ? 0.5 : 0, (row.count / published) * 100)}%`,
              }}
            />
          </span>
          <span className="coverage-value">
            {formatInt(row.count)}
            <span className="faint">{sharePercent(row.count, published)}</span>
          </span>
          <span className="coverage-note">{row.note}</span>
        </div>
      ))}
      <p className="chart-note">
        Coverage is not quality. Unscored severity remains unknown, not low; a missing forecast is
        unknown, never zero. The four measures describe different populations and are not additive.
      </p>
    </div>
  );
}
