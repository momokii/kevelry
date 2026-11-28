// The assistant's wire caps: one home for the numbers both ends enforce.
//
// The desk bounds the history it sends; the route refuses a body over the cap.
// Those are the same three numbers seen from two sides, and when they were
// declared twice they drifted — the desk sent at most 10 messages and 11 000
// characters while the route accepted 12 and 12 000. The drift was invisible
// while the client was the stricter of the two, and it was exactly the shape of
// bug the desk's own `400`s came from: a client that cannot tell what its server
// accepts will eventually build a request the server refuses.
//
// So the route's body schema imports these caps and this trim, and so does the
// desk. The route keeps the strict validation — this module only states the
// limit and the one rule for staying under it, so there is no second literal to
// drift.
//
// The numbers are the route's own, not a client-side discount: the question
// being answered is counted in the total (nothing is added after this trim), so
// a body built here at the cap is a body the route accepts, and one character
// over it is a `400` that names the limit.

/** Messages in one turn: the question, plus the settled pairs that ride with it. */
export const ASSISTANT_MAX_MESSAGES = 12;

/** Characters in one message. An answer longer than this is dropped whole. */
export const ASSISTANT_MAX_MESSAGE_CHARS = 2_000;

/** Characters across the whole history, the newest question included. */
export const ASSISTANT_MAX_TOTAL_CHARS = 12_000;

/**
 * Longest question the route accepts. A question is one message, so this is the
 * per-message cap rather than a fourth number that could drift from it.
 */
export const MAX_QUESTION_CHARS = ASSISTANT_MAX_MESSAGE_CHARS;

/** One message as it crosses the wire. */
export interface WireMessage {
  role: "user" | "assistant";
  content: string;
}

/** The part of a settled turn the wire carries: its question and its answer. */
export interface HistoryTurn {
  readonly question: string;
  readonly answer: string;
}

export interface BuiltHistory {
  /** The body's `messages`: the newest question, plus the newest turns that fit. */
  messages: WireMessage[];
  /** How many settled turns were dropped to fit the caps; 0 means nothing was. */
  droppedTurns: number;
}

/**
 * The history a turn sends, bounded before it is sent rather than after it fails.
 *
 * Three rules, and the order between them is the whole design:
 *
 *  1. **The newest question is kept in full, always.** It is what the turn is
 *     answering; a request that trimmed it would answer a different question.
 *  2. **The oldest turns go first.** A contiguous suffix is the only shape a
 *     reader can reason about: "the last few exchanges, then this question".
 *  3. **A message is never split.** Half an answer, replayed as though the model
 *     had said it, is a claim nobody made — so a turn whose answer is longer than
 *     the per-message cap is dropped whole, taking the older turns with it.
 *
 * Rule 3 is the one that bit production. The caps were enforced on the total but
 * not per message, so an answer longer than 2 000 characters made every later
 * turn a `400` — the transcript kept re-sending the same oversized answer.
 *
 * `turns` arrives already filtered to the ones worth replaying (settled, not
 * failed, not a refusal, not empty); that filter is transcript state, not a wire
 * rule. What fits is this function's only question.
 */
export function trimHistory(turns: readonly HistoryTurn[], question: string): BuiltHistory {
  const kept: WireMessage[][] = [];
  let chars = question.length;
  let messages = 1;
  let droppedTurns = 0;
  // Newest first, so what survives is the most recent end of the transcript: the
  // loop adds pairs from the back and stops at the first one that does not fit.
  for (const [offset, turn] of [...turns].reverse().entries()) {
    const pair: WireMessage[] = [
      { role: "user", content: turn.question },
      { role: "assistant", content: turn.answer },
    ];
    const pairChars = turn.question.length + turn.answer.length;
    const fits =
      messages + pair.length <= ASSISTANT_MAX_MESSAGES &&
      turn.question.length <= ASSISTANT_MAX_MESSAGE_CHARS &&
      turn.answer.length <= ASSISTANT_MAX_MESSAGE_CHARS &&
      chars + pairChars <= ASSISTANT_MAX_TOTAL_CHARS;
    if (!fits) {
      // Everything older is dropped too: a gap in the middle of a transcript is
      // worse than a transcript that simply starts later.
      droppedTurns = turns.length - offset;
      break;
    }
    kept.unshift(pair);
    chars += pairChars;
    messages += pair.length;
  }
  const history = kept.flat();
  history.push({ role: "user", content: question });
  return { messages: history, droppedTurns };
}
