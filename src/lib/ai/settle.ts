// The turn's terminal `done` frame: the one payload a brief is exported from.
//
// A settled turn reports four things — what it cost, how many tool rounds it
// spent, what its evidence could not support, and what kind of answer it was —
// and this module is the only place that writes them down. The generator in
// `turn.ts` sequences frames; it does not assemble the payload's fields.
//
// Numbers have no frame of their own: they are one line in a caution, not a step
// in the transcript, so they ride along here. They are omitted when the list is
// empty, and omitted entirely on a turn that collected no payload: with nothing
// to compare against, a number is not doubtful, it is unchecked.

import type { TurnEvidence } from "./evidence";

/** The token totals a settled turn reports. */
export interface SettledUsage {
  prompt: number;
  completion: number;
  reasoning: number;
  cacheRead: number;
}

/** The `done` frame, as the wire carries it. */
export interface AssistantDoneEvent {
  type: "done";
  /**
   * What kind of answer this was. `refusal` is set by the pre-inference scope
   * filter: the desk prints a quiet label and offers no brief or follow-ups,
   * because the question was declined, not answered and not failed. Absent means
   * an ordinary answer.
   */
  kind?: "refusal";
  usage: SettledUsage;
  costUsd: number;
  rounds: number;
  /** Ids the prose named without a tool behind them; empty when none. */
  unverified: string[];
  /**
   * Figures the prose printed that no tool payload in this turn supports, as
   * printed. Omitted when the list is empty, and omitted entirely on a turn that
   * collected no payload.
   */
  unverifiedNumbers?: string[];
}

export interface SettleInput {
  /** The turn's token totals, plus the price the provider reported for them. */
  usage: SettledUsage & { costUsd: number };
  rounds: number;
  /** The two doubt lists the evidence pass reported. */
  evidence: Pick<TurnEvidence, "unverifiedIds" | "unverifiedNumbers">;
  kind?: "refusal";
}

/**
 * The `done` frame, built from the turn's totals and its evidence.
 *
 * Field order is the wire's, not the alphabet's: `type` first so a reader can
 * classify the frame before parsing it, then the kind, then the bill, then the
 * doubt. `unverifiedNumbers` is spread last and only when it has something to
 * say, so a settled turn with no doubtful figure carries no empty array.
 */
export function settle({ usage, rounds, evidence, kind }: SettleInput): AssistantDoneEvent {
  const unverifiedNumbers = [...evidence.unverifiedNumbers];
  return {
    type: "done",
    ...(kind === undefined ? {} : { kind }),
    usage: {
      prompt: usage.prompt,
      completion: usage.completion,
      reasoning: usage.reasoning,
      cacheRead: usage.cacheRead,
    },
    costUsd: usage.costUsd,
    rounds,
    unverified: [...evidence.unverifiedIds],
    ...(unverifiedNumbers.length === 0 ? {} : { unverifiedNumbers }),
  };
}
