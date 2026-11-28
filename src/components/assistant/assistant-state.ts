// The desk's copy and its state shapes.
//
// Every fault the desk can show is built here, from a typed code the server sent
// — never from prose, never from an HTTP status alone. That is the whole reason
// this module is separate from the view: a state that exists only as a branch in
// JSX cannot be rendered in a test, and an error message that exists only inside
// a `catch` cannot be reviewed for honesty.
//
// Three rules the copy obeys:
//
//  1. Name what happened, in one sentence, without an apology and without the
//     word "unfortunately".
//  2. Always say what to do next — except where the answer is "wait", which is
//     stated with the time remaining instead of a call to action.
//  3. Never invent a duration, a reason, or a variable. If the server did not
//     send the reset instant or the disabled reason, the desk says what it knows
//     and stops there.

import type { AssistantImageMime } from "./assistant-image";
import type { AssistantStreamErrorCode } from "@/lib/ai/turn";

/** Longest question the route accepts; the composer enforces the same number. */
export const MAX_QUESTION_CHARS = 2000;

/**
 * The counter appears only near the limit: a character count that is always on
 * screen is a form telling the reader about itself instead of about the corpus.
 */
export const QUESTION_COUNTER_VISIBLE_AT = 1800;

export type AssistantFaultKind = "error" | "rate-limited" | "budget" | "disabled";

export type AssistantDisabledReason = "off" | "no-key" | "over-budget" | "invalid-config";

export type AssistantBudgetReason = "daily" | "session";

export interface AssistantFault {
  kind: AssistantFaultKind;
  /** The typed code, printed in the ledger line so the state is greppable. */
  code: string;
  /** What happened, in one sentence. */
  headline: string;
  /** What to do next. */
  next: string;
  /** A server-authored detail, only when it carries a fact the headline lacks. */
  detail: string | null;
  /** Whether the same question may be asked again unchanged. */
  retryable: boolean;
  disabledReason: AssistantDisabledReason | null;
  /** The exact variable an operator sets, for the disabled and budget states. */
  envVar: string | null;
  budgetReason: AssistantBudgetReason | null;
  /** ISO instant a budget resets, when the server sent one. */
  resetAt: string | null;
  /** Seconds until a rate limit lifts, when the server sent one. */
  retryAfterSeconds: number | null;
}

/** One tool call, as the provenance ledger states it. */
export interface AssistantToolLine {
  id: string;
  name: string;
  /** Rendered arguments, one line. */
  args: string;
  rows: number;
  ok: boolean;
  /** Record ids the call returned (the server's display sample). */
  ids: string[];
  /**
   * The host a successful `fetch_authoritative` call read.
   *
   * Set by the server on the `tool` frame, because the URL that answered can
   * differ from the one the model asked for when a single allow-listed redirect
   * was followed. Absent (or null) for every other call.
   */
  web?: { url: string; host: string } | null;
}

/**
 * The screenshot a turn was asked about, as the turn's record keeps it.
 *
 * No `dataUrl`: the payload lives in the composer's context state and nowhere
 * else, so a transcript of ten attached turns is ten small pictures rather than
 * ten megabytes of base64.
 */
export interface AssistantTurnImage {
  /** The attachment's session id; equal to the in-context image's id while it is sent. */
  id: number;
  name: string;
  mime: AssistantImageMime;
  size: number;
  thumb: string;
}

export interface AssistantTurn {
  id: string;
  question: string;
  answer: string;
  /** True once the turn ended, however it ended. */
  settled: boolean;
  /** True when the reader pressed Stop before the answer finished. */
  stopped: boolean;
  /**
   * True when a fault ended this turn before it finished.
   *
   * Distinct from `stopped`: the reader did not do this, the provider or the
   * connection did. A failed turn keeps whatever prose arrived, says on screen
   * that it stopped there, and is never sent back as conversation history —
   * half an answer replayed to a model reads as a claim that was made.
   */
  failed: boolean;
  /** Record ids from the server's `citations` event — never parsed from prose. */
  /**
   * True when the server declined the question as outside scope.
   *
   * A refusal is an answer: it is settled, not failed, it carries no fault
   * panel, and it offers neither follow-ups nor an export — there is nothing to
   * follow up and nothing to cite. Absent means an ordinary answer.
   */
  refusal?: boolean;
  citations: string[];
  /**
   * Ids the prose named that no tool returned. Reported by the server, never
   * derived from the answer in the browser: the verified set lives server-side.
   */
  unverified: string[];
  tools: AssistantToolLine[];
  /** The pinned record this question was asked about. */
  aboutCve: string | null;
  /**
   * Whether *this* question's request carried the screenshot.
   *
   * Consent is per turn, decided once at send time and then stored, because the
   * composer's state moves on: a reader who removes the chip is telling the desk
   * what to do next, not what happened three questions ago. The turn is the only
   * place the answer to "did this question send the picture?" can be read, and
   * the label under the thumbnail is that answer — never a re-derivation.
   */
  sendImage: boolean;
  /** The screenshot this question sent, or null when it carried none. */
  image: AssistantTurnImage | null;
  /**
   * True when this question's request had to drop earlier turns to fit the
   * route's limits.
   *
   * Stored on the turn rather than derived at render time: the transcript keeps
   * growing, so "would this request have been trimmed?" has a different answer
   * every time it is asked. The turn is the only record of what that request
   * actually carried.
   */
  contextTrimmed: boolean;
}

/**
 * The one-line note a turn shows when its request dropped earlier turns.
 *
 * Quiet by design: the answer is unaffected, but the model did not see the start
 * of the conversation, and a reader who asked a follow-up deserves to know why
 * the answer stopped referring to it.
 */
export const HISTORY_TRIMMED_NOTE =
  "Earlier turns were trimmed from context to stay within limits.";

/** The feature gate as the page found it, rendered, never re-evaluated client-side. */
export type AssistantGate = { enabled: true } | { enabled: false; reason: AssistantDisabledReason };

const ERROR_COPY: Record<string, { headline: string; next: string; retryable: boolean }> = {
  AI_TIMEOUT: {
    headline: "The model took too long; the question was not answered.",
    next: "Ask again, or narrow the question to one record.",
    retryable: true,
  },
  AI_UPSTREAM_ERROR: {
    headline: "The provider failed before the answer finished.",
    next: "Ask again. If it fails twice, the provider is the problem, not this corpus.",
    retryable: true,
  },
  AI_TRUNCATED: {
    headline: "The answer was cut off; ask a narrower question.",
    next: "Ask about one record, or one list, at a time.",
    retryable: true,
  },
  AI_EMPTY_ANSWER: {
    // The model spent every round of the turn on tools and never wrote prose,
    // or a round came back cleanly with nothing in it. The turn is a fault, not
    // a settled reply with nothing in it, so the desk says what went wrong and
    // offers the one thing that can help: a smaller question.
    headline: "The model used every round of the turn without writing an answer.",
    next: "Ask again, or narrow the question to one record so it needs fewer lookups.",
    retryable: true,
  },
  // A refusal has no entry here on purpose: it is not a fault. The server sends
  // it as a settled answer with `done.kind: "refusal"`, and the desk renders
  // the quiet note beside the prose instead of an alert panel.
  BAD_QUERY: {
    headline: "The question could not be sent as written.",
    next: "Rephrase it as a question about a CVE record or this corpus.",
    retryable: true,
  },
  BAD_ID: {
    headline: "That record id is not a CVE id.",
    next: "Use the form CVE-YYYY-NNNN, then ask again.",
    retryable: true,
  },
  BAD_IMAGE: {
    headline: "The image was refused.",
    next: "Use a PNG, JPEG, or WebP under 1.5 MB.",
    retryable: true,
  },
  BAD_REQUEST: {
    headline: "The question was refused before the model saw it.",
    next: "Reload the page and ask again; if it repeats, the transcript was too long for one turn.",
    retryable: false,
  },
  PAYLOAD_TOO_LARGE: {
    headline: "The question was too large to send.",
    next: "Shorten the transcript, or remove the screenshot and ask about one record.",
    retryable: true,
  },
  INTERNAL: {
    headline: "The server failed while answering.",
    next: "Ask again in a moment. Nothing about the question was stored.",
    retryable: true,
  },
};

/** Fallback copy for a code this build does not know. Never shows the raw code as prose. */
const UNKNOWN_ERROR = {
  headline: "The answer stopped unexpectedly.",
  next: "Ask again, or check the deployment's source status page.",
  retryable: true,
};

const DISABLED_VARIABLE: Record<AssistantDisabledReason, string> = {
  off: "AI_ENABLED",
  "no-key": "AI_API_KEY",
  "over-budget": "AI_DAILY_BUDGET_USD",
  "invalid-config": "AI_ENABLED",
};

const DISABLED_HEADLINE: Record<AssistantDisabledReason, string> = {
  off: "The assistant is turned off on this deployment.",
  "no-key": "The assistant has no gateway key, so it is disabled.",
  "over-budget": "The assistant has spent today's budget.",
  "invalid-config": "The assistant's configuration is not valid.",
};

const DISABLED_NEXT: Record<AssistantDisabledReason, string> = {
  off: "An operator enables it by setting AI_ENABLED=true and AI_API_KEY, then restarting the app.",
  "no-key": "An operator sets AI_API_KEY at runtime — the key is never baked into the image.",
  "over-budget":
    "The daily cap resets at 00:00 UTC; raising AI_DAILY_BUDGET_USD is the operator's call.",
  "invalid-config":
    "An operator corrects AI_ENABLED, AI_API_KEY or AI_MAX_TOKENS in the environment.",
};

function baseFault(
  overrides: Partial<AssistantFault> & Pick<AssistantFault, "kind" | "code">,
): AssistantFault {
  return {
    headline: UNKNOWN_ERROR.headline,
    next: UNKNOWN_ERROR.next,
    detail: null,
    retryable: UNKNOWN_ERROR.retryable,
    disabledReason: null,
    envVar: null,
    budgetReason: null,
    resetAt: null,
    retryAfterSeconds: null,
    ...overrides,
  };
}

/** A feature-disabled state: the page's gate, or an `AI_DISABLED` event. */
export function disabledFault(reason: AssistantDisabledReason): AssistantFault {
  return baseFault({
    kind: "disabled",
    code: "AI_DISABLED",
    headline: DISABLED_HEADLINE[reason],
    next: DISABLED_NEXT[reason],
    retryable: false,
    disabledReason: reason,
    envVar: DISABLED_VARIABLE[reason],
  });
}

export interface BudgetFaultInput {
  reason: AssistantBudgetReason;
  resetAt: string | null;
}

/**
 * Budget exhaustion. The two caps are different facts and are never merged: the
 * daily cap is money the deployment spent, the session cap is this transcript's
 * token estimate. Both say which one ran out.
 */
export function budgetFault(input: BudgetFaultInput): AssistantFault {
  const daily = input.reason === "daily";
  return baseFault({
    kind: "budget",
    code: "AI_BUDGET_EXHAUSTED",
    headline: daily
      ? "The assistant has spent today's AI budget."
      : "This transcript has reached its token budget.",
    next: daily
      ? "The budget resets at 00:00 UTC. The composer unlocks when it does, or an operator raises AI_DAILY_BUDGET_USD."
      : "Start a new question in a fresh tab — this transcript is the only thing counted, and nothing is stored server-side.",
    retryable: false,
    budgetReason: input.reason,
    envVar: daily ? "AI_DAILY_BUDGET_USD" : "AI_SESSION_BUDGET_TOKENS",
    resetAt: input.resetAt,
  });
}

/** A 429 from the route, carrying the wait it reported. */
export function rateLimitedFault(retryAfterSeconds: number): AssistantFault {
  return baseFault({
    kind: "rate-limited",
    code: "RATE_LIMITED",
    headline: "The assistant is rate limited on this connection.",
    next: "Wait for the window to reset. The composer unlocks on its own; nothing is lost.",
    retryable: false,
    retryAfterSeconds,
  });
}

/** A typed error event from inside the stream, or a pre-stream typed failure. */
export function faultFromCode(code: string, detail: string | null = null): AssistantFault {
  if (code === "AI_DISABLED") {
    // A stream event carries no reason: the gate said why at page load, and this
    // path means the gate changed underneath the page. State the fact, not a
    // guessed cause.
    return baseFault({
      kind: "disabled",
      code: "AI_DISABLED",
      headline: "The assistant was disabled while this page was open.",
      next: "Reload once an operator has set AI_ENABLED and AI_API_KEY. Nothing was stored.",
      retryable: false,
      envVar: "AI_ENABLED",
    });
  }
  if (code === "AI_BUDGET_EXHAUSTED") return budgetFault({ reason: "daily", resetAt: null });
  const copy = ERROR_COPY[code] ?? UNKNOWN_ERROR;
  return baseFault({
    kind: "error",
    code,
    headline: copy.headline,
    next: copy.next,
    retryable: copy.retryable,
    detail,
  });
}

/**
 * Maps an in-stream `error` event. The event's own message is not used: it is
 * written for an operator, and the desk speaks in one voice.
 */
export function faultFromStreamError(code: AssistantStreamErrorCode): AssistantFault {
  return faultFromCode(code);
}

export interface HttpFaultInput {
  status: number;
  /** Parsed JSON error body, when there was one. */
  snapshot: unknown;
  retryAfterSeconds: number | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function detailsOf(body: Record<string, unknown> | null): Record<string, unknown> | null {
  return body === null ? null : asRecord(body["details"]);
}

function readString(source: Record<string, unknown> | null, key: string): string | null {
  if (source === null) return null;
  const value = source[key];
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * Maps a pre-stream HTTP failure. The route's error envelope is the v1 shape:
 * `{ code, message, details }`, with `Retry-After` on a 429 — so a 429 without
 * a `Retry-After` still becomes the rate-limited state, with a one-second wait,
 * rather than an unactionable "something failed".
 */
export function faultFromHttp(input: HttpFaultInput): AssistantFault {
  const body = asRecord(input.snapshot);
  const details = detailsOf(body);
  const code = readString(body, "code") ?? (input.status === 429 ? "RATE_LIMITED" : "INTERNAL");
  const message = readString(body, "message");
  const reason = readString(details, "reason");
  const resetAt = readString(details, "resetAt");

  if (code === "AI_DISABLED") {
    const disabledReason: AssistantDisabledReason =
      reason === "no-key" || reason === "over-budget" || reason === "invalid-config"
        ? reason
        : "off";
    return { ...disabledFault(disabledReason), detail: message };
  }
  if (code === "AI_BUDGET_EXHAUSTED") {
    return budgetFault({
      reason: reason === "session" ? "session" : "daily",
      resetAt,
    });
  }
  if (code === "RATE_LIMITED") {
    return rateLimitedFault(Math.max(1, input.retryAfterSeconds ?? 1));
  }
  return { ...faultFromCode(code, null), detail: null };
}

// ---------------------------------------------------------------------------
// Wording helpers
// ---------------------------------------------------------------------------

const TOOL_VERBS: Record<string, string> = {
  search_cves: "searching the corpus",
  get_cve: "reading the record",
  epss_history: "reading the EPSS history",
  kev_window: "checking the KEV window",
  coverage_stats: "reading corpus coverage",
  list_priority: "ranking a priority list",
  cwe_lookup: "looking up the weakness class",
  fetch_authoritative: "reading an authoritative page",
};

/** The streaming line: what the server is doing right now, in words. */
export function toolActivity(name: string, rows: number): string {
  const verb = TOOL_VERBS[name] ?? "running a tool";
  if (!Number.isFinite(rows) || rows <= 0) return `${verb} · no rows yet…`;
  return `${verb} · ${String(rows)} ${rows === 1 ? "record" : "records"}…`;
}

/** Arguments on one line: `days=30`, `id=CVE-2021-44228`, strings quoted. */
export function formatToolArgs(args: unknown): string {
  if (args === null || args === undefined) return "no arguments";
  if (typeof args !== "object" || Array.isArray(args)) return JSON.stringify(args);
  const entries = Object.entries(args as Record<string, unknown>);
  if (entries.length === 0) return "no arguments";
  return entries.map(([key, value]) => `${key}=${formatArgValue(value)}`).join(" · ");
}

function formatArgValue(value: unknown): string {
  if (typeof value === "string") {
    // Ids and day counts are the common case; quote only what needs it.
    return /^[A-Za-z0-9_.:-]+$/.test(value) ? value : JSON.stringify(value);
  }
  if (value === null || value === undefined) return "null";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

const COUNT_FORMAT = new Intl.NumberFormat("en-US");

/**
 * The caution line for ids the dataset never returned.
 *
 * One sentence, with the ids spelled out: the reader has to be able to see which
 * id is doubtful, not just that something is. Singular and plural are written
 * separately because "1 record ids" is the kind of detail that makes a warning
 * read as machine output.
 */
export function unverifiedNote(ids: readonly string[]): string {
  const count = ids.length;
  const lead =
    count === 1
      ? "1 record id in this answer was not found in the dataset"
      : `${formatCount(count)} record ids in this answer were not found in the dataset`;
  const tail =
    count === 1
      ? "It may be a typo or a record this deployment does not hold."
      : "They may be typos or records this deployment does not hold.";
  return `${lead}: ${ids.join(", ")}. ${tail}`;
}

export function formatCount(count: number): string {
  return COUNT_FORMAT.format(count);
}

/**
 * The quiet label on a refusal.
 *
 * Deliberately not a fault sentence: a refusal is the desk answering the only
 * way it can, so the label says what the answer is not, states the reason in
 * two words, and stops. The server sets `done.kind: "refusal"`; this is the one
 * place the desk turns that into words.
 */
export const REFUSAL_LABEL = "Not answered — outside scope";

/**
 * The stage line of the working row: what the turn is doing, never how long it
 * will take. The tool's own words win; otherwise the state of the answer does.
 */
export function workingStage(turn: AssistantTurn, activity: string | null): string {
  if (activity !== null) return activity;
  if (turn.answer !== "") return "writing…";
  if (turn.tools.length > 0) return "reading what the last call returned…";
  return "the model is deciding what to look up…";
}

/**
 * The progress line for a round the server is re-running.
 *
 * A `retry` frame is not a fault: the turn is still working, and the reader is
 * owed the one fact that explains the extra wait. The two codes are different
 * facts — a round cut by its completion cap, and a round that came back clean
 * with nothing in it — so each gets its own words rather than one guess.
 */
export const RETRY_STAGE = {
  AI_EMPTY_ANSWER: "the first attempt came back empty — retrying",
  AI_TRUNCATED: "the first attempt was cut off — retrying",
} as const satisfies Record<"AI_TRUNCATED" | "AI_EMPTY_ANSWER", string>;

export function retryStage(code: "AI_TRUNCATED" | "AI_EMPTY_ANSWER"): string {
  return RETRY_STAGE[code];
}

/** Only an `https:` URL may become a link, whatever the ledger carries. */
function isHttpsUrl(raw: string): boolean {
  try {
    return new URL(raw).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * The web evidence a turn carries: one entry per distinct fetched URL.
 *
 * Derived from the ledger, never from the prose. The chip exists because a
 * `fetch_authoritative` call actually answered, and it links the URL the server
 * reported reading — not a URL the answer happened to mention. Three guards
 * keep it honest: a failed call contributes nothing, only an `https:` URL
 * becomes a link, and a repeated URL is one chip.
 */
export function webSources(
  turn: Pick<AssistantTurn, "tools">,
): Array<{ url: string; host: string }> {
  const seen = new Set<string>();
  const sources: Array<{ url: string; host: string }> = [];
  for (const line of turn.tools) {
    const web = line.web ?? null;
    if (!line.ok || web === null || seen.has(web.url) || !isHttpsUrl(web.url)) continue;
    seen.add(web.url);
    sources.push({ url: web.url, host: web.host });
  }
  return sources;
}

/** How often the elapsed counter ticks. Four a second: tenths move visibly. */
export const ELAPSED_TICK_MS = 250;

/**
 * The elapsed readout: tenths under ten seconds, whole seconds after. A wait
 * that feels static gets a digit that moves; a wait that is obviously long does
 * not need one. Always inside a fixed-width, tabular span, so it cannot jitter.
 */
export function formatElapsed(elapsedMs: number): string {
  const ms = Number.isFinite(elapsedMs) && elapsedMs > 0 ? elapsedMs : 0;
  if (ms < 10_000) return `${(Math.floor(ms / 100) / 10).toFixed(1)}s`;
  return `${String(Math.floor(ms / 1000))}s`;
}

/** `43 s`, `2 m 05 s`, `5 h 41 m` — coarse above a minute, exact below it. */
export function formatRemaining(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  if (seconds < 60) return `${String(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${String(minutes)} m ${String(seconds % 60).padStart(2, "0")} s`;
  const hours = Math.floor(minutes / 60);
  return `${String(hours)} h ${String(minutes % 60).padStart(2, "0")} m`;
}

/** `00:00 UTC`, or null when the instant is absent or malformed. */
export function formatResetInstant(iso: string | null): string | null {
  if (iso === null) return null;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  const at = new Date(ms);
  return `${String(at.getUTCHours()).padStart(2, "0")}:${String(at.getUTCMinutes()).padStart(2, "0")} UTC`;
}

/** Seconds between now and an instant; null when the instant is unusable. */
export function secondsUntil(iso: string | null, nowMs: number): number | null {
  if (iso === null) return null;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return Math.max(0, Math.round((ms - nowMs) / 1000));
}

/** The counter is a near-limit warning, not a permanent rubric. */
export function counterVisible(length: number): boolean {
  return length >= QUESTION_COUNTER_VISIBLE_AT;
}
