// The numeric sibling of the record-id check.
//
// The prompt forbids every figure that is not in a tool result. Until now only
// ids were checked, so a model could write "99.2%" and the desk printed it as
// though a tool had said it. This is the check for numbers: the prose is scanned
// for the shapes a reader would act on, the turn's tool payloads are scanned for
// every value they contain, and anything the prose printed that the payloads
// cannot support is reported — never edited out, because the reader is owed the
// sentence and the doubt.
//
// It is deliberately conservative, because a checker that accuses an honest
// answer is worse than no checker at all:
//
//   - small integers (0–999) are ignored: list numbering, "two records" and
//     "30 days" are not claims this pass can adjudicate;
//   - a bare year is ignored (1990–2035), because "in 2026" is prose, not a
//     figure; the same year inside an ISO date is part of the date, which is
//     checked;
//   - a record id's digits are never numbers: `CVE-2021-44228` would otherwise
//     accuse `44228` on every answer that names a record;
//   - a value matches with the tolerance its own printed precision allows, so
//     a legitimate rounding (99.18% printed as 99.2%) verifies instead of
//     being flagged.
//
// The four checked shapes are percentages, decimals with at least three
// fractional digits (EPSS probabilities and CVSS vectors), integers of 1000 or
// more (counts), and ISO dates.

import { CVE_ID_BODY } from "../cve-id";

/** What kind of number the prose printed, which decides how it is matched. */
export type AnswerNumberKind = "percent" | "decimal" | "integer" | "date";

export interface AnswerNumber {
  /** Exactly as printed: `99.999%`, `4,110`, `2026-11-22`. */
  text: string;
  kind: AnswerNumberKind;
  /** The value the token denotes, separators stripped. `null` for a date. */
  value: number | null;
}

/** Below this an integer is a list marker, an ordinal or a small count. */
export const CHECKED_INTEGER_MIN = 1000;

/** A bare year in this range is prose, not a figure. */
export const IGNORED_YEAR_MIN = 1990;
export const IGNORED_YEAR_MAX = 2035;

/** The widest tolerance a percentage claim is given, in percentage points. */
export const PERCENT_TOLERANCE_POINTS = 0.01;

/** Upper bound on the values one turn's payloads contribute, for a big fetch. */
const PAYLOAD_VALUE_CAP = 20_000;

/**
 * Record ids in the prose, removed before the scan.
 *
 * Wider than the plan's "inline code that is a CVE id": an id written in plain
 * prose carries the same digits, and skipping only the backticked ones would
 * flag `44228` in every answer that names a record. CWE ids go with them for the
 * same reason — they are references, not figures.
 */
const RECORD_ID_SPAN = new RegExp(`\\b(?:${CVE_ID_BODY}|CWE-[0-9]{1,5})\\b`, "gi");

/** ISO `2026-11-22`. The `T` and the clock of a timestamp are not the claim. */
const DATE_BODY = "[0-9]{4}-[0-9]{2}-[0-9]{2}";
/** A sign is a sign only where a token starts, never the dash of a range. */
const START = "(?<![0-9.,-])";

/**
 * One pass, four shapes, in an order that makes each token whole.
 *
 * The date comes first so its year is never read as a count; the percentage
 * comes before the decimal so `99.999%` is one claim rather than two. The
 * lookbehinds keep a match from starting inside a longer number (`204` of
 * `1,204`, `99999` of `0.99999`), and the lookaheads keep a match from ending
 * inside one.
 */
const NUMBER_TOKEN = new RegExp(
  [
    `(?<![0-9])(${DATE_BODY})(?![0-9])`,
    `${START}(-?[0-9][0-9,]*(?:\\.[0-9]+)?%)`,
    `${START}(-?[0-9]+\\.[0-9]{3,})(?![0-9%])`,
    `${START}(-?[0-9]{1,3}(?:,[0-9]{3})+|-?[0-9]{4,})(?![0-9.,%])`,
  ].join("|"),
  "g",
);

/** One matched token, or `null` when the text cannot be read as a value. */
function toToken(match: RegExpExecArray): AnswerNumber | null {
  const [text, dateText, percentText, decimalText, integerText] = match;
  if (dateText !== undefined) return { text: dateText, kind: "date", value: null };
  if (percentText !== undefined) {
    const value = Number(percentText.replace(/[,%]/g, ""));
    return Number.isFinite(value) ? { text: percentText, kind: "percent", value } : null;
  }
  if (decimalText !== undefined) {
    const value = Number(decimalText);
    return Number.isFinite(value) ? { text: decimalText, kind: "decimal", value } : null;
  }
  if (integerText !== undefined) {
    const value = Number(integerText.replace(/,/g, ""));
    return Number.isFinite(value) ? { text: integerText, kind: "integer", value } : null;
  }
  return null;
}

/** Every number-shaped token in a text, unfiltered and undeduped. */
function scanNumbers(text: string): AnswerNumber[] {
  const found: AnswerNumber[] = [];
  for (const match of text.matchAll(NUMBER_TOKEN)) {
    const token = toToken(match);
    if (token !== null) found.push(token);
  }
  return found;
}

/** True when this token is a claim the pass is willing to check at all. */
function isClaim(token: AnswerNumber): boolean {
  if (token.kind !== "integer") return true;
  const value = token.value ?? 0;
  if (value >= IGNORED_YEAR_MIN && value <= IGNORED_YEAR_MAX) return false;
  return value >= CHECKED_INTEGER_MIN;
}

/**
 * The figures the answer printed, deduplicated and in the order they appeared.
 *
 * One extraction rule for the whole pass: a repeated number is one claim, and
 * the printed form is what the reader is shown back (`4,110`, not `4110`).
 */
export function extractAnswerNumbers(text: string): AnswerNumber[] {
  const found: AnswerNumber[] = [];
  const seen = new Set<string>();
  for (const token of scanNumbers(text.replace(RECORD_ID_SPAN, " "))) {
    if (!isClaim(token)) continue;
    const key = token.kind === "date" ? token.text : `${token.kind}:${String(token.value)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    found.push(token);
  }
  return found;
}

/** What one turn's tool payloads can support, in the shapes the scan produces. */
export interface PayloadNumbers {
  /** Every number the payloads contained, at any depth, as a raw value. */
  values: number[];
  /** The subset printed with a `%`, kept in percentage points. */
  percents: number[];
  /** ISO dates, including the date part of a timestamp. */
  dates: Set<string>;
  /** Tokens exactly as a payload wrote them, for the exact-substring rule. */
  texts: Set<string>;
}

/**
 * Everything a turn's tool results contain, flattened.
 *
 * Walks values rather than the serialised JSON, so a number stays a number:
 * comparing `0.99999` to `"0.99999"` as text is how an exact match gets missed.
 * Strings are scanned too, because a payload states `epssText` and `retrievedAt`
 * as text. Depth and count are bounded: a hostile or merely enormous payload
 * (`fetch_authoritative` returns 256 KB) must not turn this into a walk of a
 * huge object graph.
 */
export function collectPayloadNumbers(payloads: readonly unknown[]): PayloadNumbers {
  const haystack: PayloadNumbers = {
    values: [],
    percents: [],
    dates: new Set<string>(),
    texts: new Set<string>(),
  };

  const add = (token: AnswerNumber): void => {
    haystack.texts.add(token.text);
    if (token.kind === "date") {
      haystack.dates.add(token.text);
      return;
    }
    if (token.value === null) return;
    haystack.values.push(token.value);
    if (token.kind === "percent") haystack.percents.push(token.value);
  };

  const walk = (node: unknown, depth: number): void => {
    if (haystack.values.length >= PAYLOAD_VALUE_CAP || depth > 6) return;
    if (typeof node === "number") {
      if (Number.isFinite(node)) haystack.values.push(node);
      return;
    }
    if (typeof node === "string") {
      for (const token of scanNumbers(node)) add(token);
      return;
    }
    if (Array.isArray(node)) {
      for (const entry of node) walk(entry, depth + 1);
      return;
    }
    if (typeof node === "object" && node !== null) {
      for (const entry of Object.values(node)) walk(entry, depth + 1);
    }
  };

  for (const payload of payloads) walk(payload, 0);
  return haystack;
}

/** How many fractional digits a token printed; `99.999%` is three. */
function fractionDigits(text: string): number {
  const dot = text.indexOf(".");
  if (dot === -1) return 0;
  const percent = text.indexOf("%");
  const end = percent === -1 ? text.length : percent;
  return Math.max(0, end - dot - 1);
}

/**
 * The tolerance a percentage claim earns, in percentage points.
 *
 * ±0.01 points is the floor, widened to one unit of the printed last digit: a
 * model that prints one decimal (`99.2%`) is rounding a payload's `99.18%`, and
 * a checker that calls that a fabrication would be wrong. A two- or three-digit
 * printing is held to the same unit, so `99.2%` cannot absorb a payload's
 * `99.999%`.
 */
function percentTolerance(text: string): number {
  return Math.max(PERCENT_TOLERANCE_POINTS, 10 ** -fractionDigits(text));
}

/** One unit of the printed last digit: `0.9999` verifies `0.99999`. */
function decimalTolerance(text: string): number {
  return 10 ** -fractionDigits(text);
}

/**
 * Whether a payload can support one printed figure.
 *
 * Percentages are compared in both readings a payload may use — the number as
 * printed in points (`99.999`) and as a probability (`0.99999`) — because EPSS
 * stores one and prose prints the other. Integers are exact once separators are
 * stripped, and dates are exact strings: a count and a day are not approximate.
 */
function verifies(token: AnswerNumber, haystack: PayloadNumbers): boolean {
  if (haystack.texts.has(token.text)) return true;
  if (token.kind === "date") return haystack.dates.has(token.text);
  const value = token.value;
  if (value === null) return false;

  if (token.kind === "integer") return haystack.values.includes(value);

  if (token.kind === "percent") {
    const tolerancePoints = percentTolerance(token.text);
    const toleranceFraction = tolerancePoints / 100;
    const fraction = value / 100;
    for (const number of haystack.values) {
      if (Math.abs(value - number) <= tolerancePoints) return true;
      if (Math.abs(fraction - number) <= toleranceFraction) return true;
    }
    for (const percent of haystack.percents) {
      if (Math.abs(fraction - percent / 100) <= toleranceFraction) return true;
    }
    return false;
  }

  const tolerance = decimalTolerance(token.text);
  const asPoints = value * 100;
  for (const number of haystack.values) {
    if (Math.abs(value - number) <= tolerance) return true;
    if (Math.abs(asPoints - number) <= tolerance * 100) return true;
  }
  for (const percent of haystack.percents) {
    if (Math.abs(asPoints - percent) <= tolerance * 100) return true;
  }
  return false;
}

/**
 * The figures the prose printed that this turn's tool results cannot support.
 *
 * `payloads` is every successful tool result of the turn. An empty list is not
 * evidence of a wrong number — there is nothing to compare against — so nothing
 * is reported: a page with no evidence must not be accused. A refusal never
 * reaches this function at all.
 */
export function unverifiedAnswerNumbers(text: string, payloads: readonly unknown[]): string[] {
  if (payloads.length === 0) return [];
  const haystack = collectPayloadNumbers(payloads);
  return extractAnswerNumbers(text)
    .filter((token) => !verifies(token, haystack))
    .map((token) => token.text);
}
