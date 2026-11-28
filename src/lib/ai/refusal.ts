// A refusal is an answer, not a fault.
//
// `preScreen` rejects the clearest out-of-scope questions before any inference,
// at $0. That rejection used to be a `422 AI_REFUSED`, which put the one thing
// the desk understood and deliberately declined into the fault panel — the
// place the reader is told something broke. Nothing broke.
//
// So a refusal is an SSE turn like any other: the sentence streams as prose, the
// citation set is empty because no tool ran, and `done` carries
// `kind: "refusal"` so the desk prints a quiet label instead of an alert. There
// is no provider call and no ledger row — a refusal costs nothing to write, and
// billing a success for one would make the daily budget a lie.
//
// The copy does the one thing a refusal has to do: it names what the desk can
// do, and it offers two next steps the eight record tools can actually answer.
// It opens with `REFUSAL_TEMPLATE`, the same sentence the prompt gives the model
// for a refusal it decides on its own, so a code refusal and a model refusal
// read in one voice.

import { REFUSAL_TEMPLATE } from "./prompt";
import type { AssistantEvent } from "./turn";

/**
 * The two next steps a refusal offers.
 *
 * Both are answerable from this deployment's own records — a KEV window and a
 * two-record comparison — so a refused question ends with an invitation the
 * dataset can honour, never with "try asking something else".
 */
export const REFUSAL_NEXT_STEPS: readonly string[] = [
  "Which KEV entries were added in the last 30 days? — answered with the catalog rows this deployment holds, and their count.",
  "Compare two records by id — publication date, primary CVSS, KEV state and catalog date, latest EPSS, field by field.",
];

/**
 * The refusal, as the reader reads it.
 *
 * Plain prose plus one short list: the desk's answer renderer formats it like
 * any other answer, because that is what it is.
 */
export function refusalAnswer(): string {
  return [
    REFUSAL_TEMPLATE,
    "Two questions this desk can answer from these records:",
    ...REFUSAL_NEXT_STEPS.map((step) => `- ${step}`),
  ].join("\n\n");
}

/**
 * The refusal turn: one prose frame, an empty citation set, and a `done` that
 * says what kind of answer this was.
 *
 * A generator rather than an array so the route pumps it exactly like a
 * provider-backed turn — one SSE response builder, one frame encoder, one
 * terminal frame. No client, no database, no ledger: every count here is zero
 * because nothing was read and nothing was spent.
 */
export async function* runRefusalTurn(): AsyncGenerator<AssistantEvent> {
  yield { type: "delta", text: refusalAnswer() };
  yield { type: "citations", records: [] };
  yield {
    type: "done",
    kind: "refusal",
    usage: { prompt: 0, completion: 0, reasoning: 0, cacheRead: 0 },
    costUsd: 0,
    rounds: 0,
    unverified: [],
  };
}
