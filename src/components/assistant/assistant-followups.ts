// Follow-ups, derived from the ledger rather than written by the model.
//
// A suggestion that mentions an id the turn never read is a hallucination with
// a button on it. So every chip here is built by code from a tool line that
// actually ran: the KEV window's own returned ids, an EPSS history call's
// argument id, a CWE lookup's argument id. No ledger line, no chip — including
// when the model mentioned the topic in prose but never fetched it.
//
// Three kinds, one per data shape, in a fixed order: KEV deadline, EPSS
// trajectory, CWE mitigation. At most three render because at most three kinds
// exist.

import type { AssistantTurn } from "./assistant-state";

export type FollowUpKind = "kev" | "epss" | "cwe";

export interface AssistantFollowUp {
  /** Stable id for the button and its test. */
  id: string;
  kind: FollowUpKind;
  /** The question the chip submits, verbatim. */
  question: string;
  /** The record or taxonomy id the question is about. */
  subject: string;
}

type ToolLines = AssistantTurn["tools"];

const CVE_ARG_PATTERN = /(?:^| · )id=(CVE-[0-9]{4}-[0-9]{4,})(?:$| · )/;
const CWE_ARG_PATTERN = /(?:^| · )cweId=(CWE-[0-9]+)(?:$| · )/i;

function firstSuccessful(lines: ToolLines, name: string): AssistantTurn["tools"][number] | null {
  return lines.find((line) => line.name === name && line.ok) ?? null;
}

/** `id=CVE-…` from the line's rendered arguments, when the tool was given one. */
function cveArg(line: AssistantTurn["tools"][number] | null): string | null {
  if (line === null) return null;
  const match = CVE_ARG_PATTERN.exec(line.args);
  return match?.[1] ?? null;
}

function cweArg(line: AssistantTurn["tools"][number] | null): string | null {
  if (line === null) return null;
  const match = CWE_ARG_PATTERN.exec(line.args);
  return match?.[1] === undefined ? null : match[1].toUpperCase();
}

/**
 * The chips for one turn. KEV first, then EPSS, then CWE: the order is the
 * order of the question a reader is most likely to ask next.
 */
export function buildFollowUps(turn: Pick<AssistantTurn, "tools">): AssistantFollowUp[] {
  const chips: AssistantFollowUp[] = [];
  const seen = new Set<string>();

  const kev = firstSuccessful(turn.tools, "kev_window");
  const kevId = kev?.ids.find((id) => /^CVE-[0-9]{4}-[0-9]{4,}$/.test(id)) ?? null;
  if (kevId !== null) {
    chips.push({
      id: "followup-kev-due",
      kind: "kev",
      question: `When is ${kevId} due?`,
      subject: kevId,
    });
    seen.add(kevId);
  }

  const epss = firstSuccessful(turn.tools, "epss_history");
  const epssId =
    cveArg(epss) ?? epss?.ids.find((id) => /^CVE-[0-9]{4}-[0-9]{4,}$/.test(id)) ?? null;
  if (epssId !== null && !seen.has(epssId)) {
    chips.push({
      id: "followup-epss-history",
      kind: "epss",
      question: `How has EPSS moved for ${epssId}?`,
      subject: epssId,
    });
    seen.add(epssId);
  }

  const cwe = firstSuccessful(turn.tools, "cwe_lookup");
  const cweId = cweArg(cwe);
  if (cweId !== null) {
    chips.push({
      id: "followup-cwe-mitigation",
      kind: "cwe",
      question: `What does ${cweId} mitigate?`,
      subject: cweId,
    });
  }

  return chips;
}
