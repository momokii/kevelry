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
// Density is a hierarchy, not a scrollbar. The rail shows the transcript's first
// three calls and six chips per call, each with its own in-place disclosure, and
// it never sets a max-height: the column is as tall as what it says. Two things
// are never collapsed — a `no rows` call and a `failed` call, because an empty
// result is the evidence that a question had no answer — and the row label is
// derived from what came back, so it cannot claim ids the server never sent.
//
// One component, two shapes: a titled column on a wide screen (`<h2>`), and a
// `<details>` disclosure below the transcript on a narrow one. The visible label
// switches with the layout, so "Evidence" is stated once either way.

"use client";

import { useState } from "react";

import { HelpTip } from "../ledger/HelpTip";
import type { AssistantToolLine, AssistantTurn } from "./assistant-state";

export interface AssistantLedgerProps {
  turns: readonly AssistantTurn[];
  /** The disclosure is open by default on a wide screen; the desk owns that. */
  open: boolean;
  onToggle: (open: boolean) => void;
}

/** Chips a single call shows before its own `+N more` disclosure. */
export const LEDGER_CHIPS_PER_CALL = 6;
/** Calls the rail shows before `See all N calls`. */
export const LEDGER_CALLS_VISIBLE = 3;

/** A call whose emptiness is the answer, and therefore is never hidden. */
function isPinned(line: AssistantToolLine): boolean {
  return !line.ok || line.rows === 0;
}

/**
 * The row label, derived from what the server actually sent.
 *
 * `rows` is the real count and `ids` is a display sample, so the two numbers are
 * stated together whenever they differ: a line reading `25 rows` beside six
 * chips is not a cap the reader can see, and `25 rows · 12 ids available` is.
 */
export function rowsLabel(line: AssistantToolLine): string {
  if (!line.ok) return "failed";
  if (line.rows === 0) return "no rows";
  const rows = `${String(line.rows)} ${line.rows === 1 ? "row" : "rows"}`;
  if (line.ids.length === 0) return `${rows} · no ids available`;
  if (line.ids.length < line.rows) {
    return `${rows} · ${String(line.ids.length)} ids available`;
  }
  return rows;
}

function callsLabel(callCount: number): string {
  if (callCount === 0) return "no tool calls yet";
  return `${String(callCount)} tool ${callCount === 1 ? "call" : "calls"}`;
}

function LedgerEntry({
  line,
  chipsOpen,
  onChipsToggle,
}: {
  line: AssistantToolLine;
  chipsOpen: boolean;
  onChipsToggle: (id: string) => void;
}) {
  const hiddenChips = line.ids.length - LEDGER_CHIPS_PER_CALL;
  const shown = chipsOpen ? line.ids : line.ids.slice(0, LEDGER_CHIPS_PER_CALL);
  return (
    <li className="assistant-ledger-entry" data-testid="assistant-ledger-entry">
      <div className="assistant-ledger-line">
        <span className="assistant-ledger-tool">{line.name}</span>
        <span
          className={`assistant-ledger-rows${line.ok ? "" : " is-failed"}`}
          data-testid="assistant-ledger-rows"
          data-rows={String(line.rows)}
          data-ids={String(line.ids.length)}
        >
          {rowsLabel(line)}
        </span>
      </div>
      <p className="assistant-ledger-args">{line.args}</p>
      {line.ids.length > 0 ? (
        <ul
          className="assistant-chip-row"
          aria-label={`Records returned by ${line.name}`}
          data-testid="assistant-ledger-chips"
        >
          {shown.map((id) => (
            <li key={id}>
              <a className="assistant-chip" href={`/explore?q=${encodeURIComponent(id)}`}>
                <span className="assistant-chip-id">{id}</span>
              </a>
            </li>
          ))}
        </ul>
      ) : null}
      {hiddenChips > 0 ? (
        <button
          type="button"
          className="assistant-ledger-more"
          aria-expanded={chipsOpen}
          data-testid="assistant-ledger-chip-more"
          onClick={() => {
            onChipsToggle(line.id);
          }}
        >
          {chipsOpen ? "Show fewer" : `+${String(hiddenChips)} more`}
        </button>
      ) : null}
    </li>
  );
}

export function AssistantLedger({ turns, open, onToggle }: AssistantLedgerProps) {
  const lines = turns.flatMap((turn) => turn.tools);
  const callCount = lines.length;
  // Expansion is keyed by call id and lives above the entries, so a later
  // stream delta that re-renders the list cannot fold a disclosure the reader
  // opened. Nothing here closes itself.
  const [openChips, setOpenChips] = useState<ReadonlySet<string>>(() => new Set<string>());
  const [allCalls, setAllCalls] = useState(false);

  const collapsible = lines.some((line, index) => index >= LEDGER_CALLS_VISIBLE && !isPinned(line));
  const shownCalls =
    allCalls || !collapsible
      ? lines
      : lines.filter((line, index) => index < LEDGER_CALLS_VISIBLE || isPinned(line));

  const toggleChips = (id: string): void => {
    setOpenChips((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

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
          <p className="assistant-ledger-note" data-testid="assistant-ledger-legend">
            Each line is one server-side lookup{" "}
            <HelpTip term="tool call" testId="assistant-tip-tool-call">
              One question the server asked the dataset on your behalf. The answer is written from
              these results only.
            </HelpTip>
            . <strong>Rows</strong>{" "}
            <HelpTip term="rows" testId="assistant-tip-rows">
              How many records the lookup returned. A lookup that stops at its own limit says so,
              and the count is the limit, not the match total.
            </HelpTip>{" "}
            is how many records it returned; the chips are the records the answer can cite.
          </p>
          {callCount === 0 ? (
            <p className="assistant-ledger-empty" data-testid="assistant-ledger-empty">
              Nothing has run yet. The first question fills this column.
            </p>
          ) : (
            <>
              <ol className="assistant-ledger-list">
                {shownCalls.map((line) => (
                  <LedgerEntry
                    key={line.id}
                    line={line}
                    chipsOpen={openChips.has(line.id)}
                    onChipsToggle={toggleChips}
                  />
                ))}
              </ol>
              {collapsible ? (
                <button
                  type="button"
                  className="assistant-ledger-more assistant-ledger-calls"
                  aria-expanded={allCalls}
                  data-testid="assistant-ledger-calls-more"
                  onClick={() => {
                    setAllCalls((current) => !current);
                  }}
                >
                  {allCalls ? "Show fewer calls" : `See all ${String(callCount)} calls`}
                </button>
              ) : null}
            </>
          )}
        </div>
      </details>
    </aside>
  );
}
