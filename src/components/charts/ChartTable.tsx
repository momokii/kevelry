import type { ReactNode } from "react";

export interface ChartTableColumn<Row> {
  /** Stable column identity. */
  key: string;
  header: string;
  /** Render this column's cell as a `<th scope="row">` row header instead of a `<td>`. */
  rowHeader?: boolean;
  value: (row: Row, index: number) => ReactNode;
}

export interface ChartTableProps<Row> {
  /** Screen-reader caption, e.g. `Published CVE counts by UTC month`. */
  caption: string;
  columns: readonly ChartTableColumn<Row>[];
  rows: readonly Row[];
  /** Disclosure label. Defaults to `Data table`. */
  summary?: string;
  /** Explicit absence instead of a fabricated zero when there are no rows. */
  emptyMessage?: string;
  rowKey?: (row: Row, index: number) => string;
  testId?: string;
}

/**
 * The value-never-depends-on-hover fallback: the same series a chart draws,
 * as a native disclosure. `<details>` opens with keyboard or a tap and needs no
 * JavaScript at all, so the table is in the server payload even with JS off.
 *
 * It renders exactly the strings it is given: a zero row says `0`, a missing
 * observation says whatever the caller words it as, and an empty series says so
 * in words rather than drawing a row of zeros.
 */
export function ChartTable<Row>({
  caption,
  columns,
  rows,
  summary = "Data table",
  emptyMessage = "No rows in this window.",
  rowKey,
  testId,
}: ChartTableProps<Row>) {
  return (
    <details className="chart-table" data-testid={testId}>
      <summary>{summary}</summary>
      <div className="table-wrap">
        <table className="data-table">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key} scope="col">
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={Math.max(1, columns.length)}>{emptyMessage}</td>
              </tr>
            ) : (
              rows.map((row, index) => (
                <tr key={rowKey === undefined ? index : rowKey(row, index)}>
                  {columns.map((column, columnIndex) => {
                    const content = column.value(row, index);
                    const isRowHeader = column.rowHeader ?? columnIndex === 0;
                    return isRowHeader ? (
                      <th key={column.key} scope="row">
                        {content}
                      </th>
                    ) : (
                      <td key={column.key}>{content}</td>
                    );
                  })}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </details>
  );
}
