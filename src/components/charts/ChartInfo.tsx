import type { ReactNode } from "react";

export function ChartInfo({ children }: { children: ReactNode }) {
  return (
    <details className="chart-info">
      <summary>How to read</summary>
      <div className="chart-info-panel">{children}</div>
    </details>
  );
}
