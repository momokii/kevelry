// The brief: one answer, its citations, and the calls that produced it.
//
// A downloaded brief is the artifact a reader keeps after the tab is gone, so it
// has to carry its own provenance. The Markdown is built here, as a pure
// function, because the two properties that matter are testable text
// properties: every citation is an absolute link, and the footer says both
// things a reader must not have to infer — the prose is model-written, and the
// figures come from the dataset.
//
// Nothing is uploaded and nothing is stored: the caller turns this string into a
// Blob and hands it to the browser.

import type { AssistantToolLine, AssistantTurn } from "./assistant-state";

export interface BriefInput {
  turn: Pick<
    AssistantTurn,
    "id" | "question" | "answer" | "citations" | "unverified" | "unverifiedNumbers" | "tools"
  >;
  /** The model the deployment is configured with; printed, never guessed. */
  modelId: string;
  /** `window.location.origin`, so citation links resolve outside this tab. */
  origin: string;
  now?: Date;
}

/** The model-written/dataset-sourced statement every brief ends with. */
export const BRIEF_DISCLAIMER =
  "The prose above is model-written and grounded only in the records listed in this brief. Every figure comes from the dataset; the model wrote the sentences around those figures.";

/**
 * Appended only when the answer named an id no tool returned. The footer above
 * says the prose is grounded in the brief's records; this says the unverified
 * ids are the exception, so the two claims cannot contradict each other.
 */
export const BRIEF_UNVERIFIED_NOTE =
  "The ids under Unverified ids are the model's own words: no tool returned them, so this brief does not vouch for them.";

/**
 * Appended only when the answer printed a figure the tool results did not
 * contain. Same reason as the note above: the footer claims every figure comes
 * from the dataset, and this section is the exception that claim has to name.
 */
export const BRIEF_UNVERIFIED_NUMBERS_NOTE =
  "The figures under Unverified numbers were not found in this turn's tool results: they may be rounded, or written from memory.";

/** `kevelry-brief-2026-11-22.md`: dated, so two downloads never collide by name. */
export function briefFileName(now: Date = new Date()): string {
  return `kevelry-brief-${now.toISOString().slice(0, 10)}.md`;
}

function oneLine(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

/** Pipes end a table cell and a newline ends a row; both are escaped, not cut. */
function tableCell(value: string): string {
  return oneLine(value.replace(/\|/g, "\\|"));
}

function originRoot(origin: string): string {
  return origin.replace(/\/+$/, "");
}

function citationLine(origin: string, id: string): string {
  return `- [${id}](${originRoot(origin)}/explore?q=${encodeURIComponent(id)})`;
}

function toolRow(line: AssistantToolLine): string {
  return `| ${tableCell(line.name)} | ${tableCell(line.args)} | ${line.ok ? String(line.rows) : "failed"} |`;
}

/**
 * Renders the brief. Order is fixed: question, answer, citations, evidence,
 * footer — the same order the desk reads in, so the download is a copy of what
 * was on screen rather than a differently shaped document.
 */
export function buildBriefMarkdown(input: BriefInput): string {
  const { turn } = input;
  const now = input.now ?? new Date();
  const parts: string[] = [`# ${oneLine(turn.question)}`, ""];

  parts.push(`_Kevelry brief · ${now.toISOString().slice(0, 10)} · model \`${input.modelId}\`_`);
  parts.push("");
  parts.push(turn.answer.trim() === "" ? "_The answer was empty._" : turn.answer.trim());
  parts.push("");

  parts.push("## Citations");
  parts.push("");
  if (turn.citations.length === 0) {
    parts.push("No record was cited in this answer.");
  } else {
    for (const id of turn.citations) parts.push(citationLine(input.origin, id));
  }
  parts.push("");

  if (turn.unverified.length > 0) {
    // Not links: a link would claim the record exists, which is the one thing
    // this section says the brief cannot support.
    parts.push("## Unverified ids");
    parts.push("");
    parts.push(
      turn.unverified.length === 1
        ? "The answer named one record id that no tool returned this turn. It may be a typo or a record this deployment does not hold."
        : `The answer named ${String(turn.unverified.length)} record ids that no tool returned this turn. They may be typos or records this deployment does not hold.`,
    );
    parts.push("");
    for (const id of turn.unverified) parts.push(`- \`${id}\``);
    parts.push("");
  }

  if (turn.unverifiedNumbers.length > 0) {
    // Not links either: a figure has no record to open. One sentence, then the
    // figures exactly as the answer printed them, so the reader can grep the
    // prose for each one.
    parts.push("## Unverified numbers");
    parts.push("");
    parts.push(
      turn.unverifiedNumbers.length === 1
        ? "The answer printed one number that no tool result this turn contained."
        : `The answer printed ${String(turn.unverifiedNumbers.length)} numbers that no tool result this turn contained.`,
    );
    parts.push("");
    for (const number of turn.unverifiedNumbers) parts.push(`- \`${number}\``);
    parts.push("");
  }

  parts.push("## Evidence");
  parts.push("");
  if (turn.tools.length === 0) {
    parts.push("No tool call was recorded for this answer.");
  } else {
    parts.push("| Tool | Arguments | Rows |");
    parts.push("| --- | --- | --- |");
    for (const line of turn.tools) parts.push(toolRow(line));
  }
  parts.push("");

  parts.push("## About this brief");
  parts.push("");
  parts.push(BRIEF_DISCLAIMER);
  parts.push("");
  if (turn.unverified.length > 0) {
    parts.push(BRIEF_UNVERIFIED_NOTE);
    parts.push("");
  }
  if (turn.unverifiedNumbers.length > 0) {
    parts.push(BRIEF_UNVERIFIED_NUMBERS_NOTE);
    parts.push("");
  }

  return parts.join("\n");
}
