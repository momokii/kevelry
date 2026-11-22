// The provenance ledger: one line per tool call, and the records it returned.
//
// This is the desk's memorable element, because it is the only part of the page
// that proves something. Prose can claim anything; a line that says which tool
// ran with which arguments, how many rows came back and which records they were
// is a claim a reader can check against `/explore`.
//
// It is a list, not a table and not a chart: a tool call has a name, an argument
// list, a count and a set of ids, and those four facts are read top to bottom.
// Chips are real links to the record, focusable and 44px tall like every other
// standalone target in the app.
//
// One component, two shapes: a titled column on a wide screen (`<h2>`), and a
// `<details>` disclosure below the transcript on a narrow one. The visible label
// switches with the layout, so "Evidence" is stated once either way.

import type { AssistantToolLine, AssistantTurn } from "./assistant-state";

export interface AssistantLedgerProps {
  turns: readonly AssistantTurn[];
  /** The disclosure is open by default on a wide screen; the desk owns that. */
  open: boolean;
  onToggle: (open: boolean) => void;
}

function rowsLabel(line: AssistantToolLine): string {
  if (!line.ok) return "failed";
  if (line.rows === 0) return "no rows";
  return `${String(line.rows)} ${line.rows === 1 ? "row" : "rows"}`;
}

function callsLabel(callCount: number): string {
  if (callCount === 0) return "no tool calls yet";
  return `${String(callCount)} tool ${callCount === 1 ? "call" : "calls"}`;
}

function LedgerEntry({ line }: { line: AssistantToolLine }) {
  return (
    <li className="assistant-ledger-entry" data-testid="assistant-ledger-entry">
      <div className="assistant-ledger-line">
        <span className="assistant-ledger-tool">{line.name}</span>
        <span className={`assistant-ledger-rows${line.ok ? "" : " is-failed"}`}>
          {rowsLabel(line)}
        </span>
      </div>
      <p className="assistant-ledger-args">{line.args}</p>
      {line.ids.length > 0 ? (
        <ul className="assistant-chip-row" aria-label={`Records returned by ${line.name}`}>
          {line.ids.map((id) => (
            <li key={id}>
              <a className="assistant-chip" href={`/explore?q=${encodeURIComponent(id)}`}>
                <span className="assistant-chip-id">{id}</span>
              </a>
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function AssistantLedger({ turns, open, onToggle }: AssistantLedgerProps) {
  const lines = turns.flatMap((turn) => turn.tools);
  const callCount = lines.length;
  return (
    <aside
      className="assistant-ledger"
      aria-label="Provenance ledger"
      data-testid="assistant-ledger"
    >
      <h2 className="assistant-ledger-heading">
        <span>Evidence</span>
        <span className="assistant-ledger-count">{callsLabel(callCount)}</span>
      </h2>
      <details
        className="assistant-ledger-disclosure"
        data-testid="assistant-ledger-disclosure"
        open={open}
        onToggle={(event) => {
          const next = event.currentTarget.open;
          if (next !== open) onToggle(next);
        }}
      >
        <summary className="assistant-ledger-summary">
          <span className="assistant-ledger-title">Evidence</span>
          <span className="assistant-ledger-count">{callsLabel(callCount)}</span>
        </summary>
        <div className="assistant-ledger-body">
          <p className="assistant-ledger-note">
            Every line is one tool call the server ran for this transcript. The ids are the records
            that call returned — the answer text never adds a citation of its own.
          </p>
          {callCount === 0 ? (
            <p className="assistant-ledger-empty" data-testid="assistant-ledger-empty">
              Nothing has run yet. The first question fills this column.
            </p>
          ) : (
            <ol className="assistant-ledger-list">
              {lines.map((line) => (
                <LedgerEntry key={line.id} line={line} />
              ))}
            </ol>
          )}
        </div>
      </details>
    </aside>
  );
}
