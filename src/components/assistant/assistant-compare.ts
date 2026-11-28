// Comparing two records, as one deterministic question.
//
// The disclosure beside the composer only collects two ids and checks their
// shape. The question it builds is fixed text, so the same pair always produces
// the same request — a comparison that reads differently on a second submit is
// not something a reader could check.
//
// The prompt carries the matching compare rule. This module states the fields
// once, in the order the rule names them, because the two must not drift: the
// question is what the model is asked, and the rule is what it is told to do
// with every field.
//
// The id shape is not restated here: it is `CVE_ID_RE`, the one pattern every
// path, query and chip validates, so a shape the field accepts is a shape the
// route accepts.

import { CVE_ID_RE } from "../../lib/cve-id";

/** The comparison's field order. One list, used by the question and by tests. */
export const COMPARE_FIELDS = [
  "status",
  "publication date",
  "primary CVSS score and version",
  "secondary CVSS scores",
  "KEV membership and catalog due date",
  "ransomware use",
  "latest EPSS score and its date",
  "CWE list",
] as const;

export interface ComparePair {
  a: string;
  b: string;
}

export interface CompareErrors {
  a: string | null;
  b: string | null;
}

export type CompareValidation =
  { ok: true; pair: ComparePair } | { ok: false; errors: CompareErrors };

export const COMPARE_EMPTY_MESSAGE = "Enter a CVE id, like CVE-2021-44228.";
export const COMPARE_SHAPE_MESSAGE = "Use the form CVE-YYYY-NNNN.";
export const COMPARE_SAME_MESSAGE = "Pick a second record — this is the first one.";

/** Trim and uppercase: an id typed in lower case is the same id. */
export function normalizeCveId(raw: string): string {
  return raw.trim().toUpperCase();
}

/** One field, for the inline message under its input. */
export function validateCompareField(raw: string): string | null {
  if (raw.trim() === "") return COMPARE_EMPTY_MESSAGE;
  if (!CVE_ID_RE.test(normalizeCveId(raw))) return COMPARE_SHAPE_MESSAGE;
  return null;
}

/** Both fields, with the duplicate check only when each id is otherwise valid. */
export function validateComparePair(a: string, b: string): CompareValidation {
  const errors: CompareErrors = { a: validateCompareField(a), b: validateCompareField(b) };
  if (errors.a === null && errors.b === null && normalizeCveId(a) === normalizeCveId(b)) {
    errors.b = COMPARE_SAME_MESSAGE;
  }
  if (errors.a !== null || errors.b !== null) return { ok: false, errors };
  return { ok: true, pair: { a: normalizeCveId(a), b: normalizeCveId(b) } };
}

/**
 * The question. It names both ids, the field order, and the three behaviours the
 * comparison must not lose: no omitted field, an explicit missing-from-dataset
 * statement, and no fused score or winner.
 */
export function buildCompareQuestion(pair: ComparePair): string {
  return [
    `Compare ${pair.a} and ${pair.b} field by field.`,
    `Cover every field in this order, without omitting one: ${COMPARE_FIELDS.join(", ")}.`,
    "Read both records with the tools before comparing them, and show each record's own value for every field.",
    "If a field is missing from the dataset for one record, say that it is missing from the dataset for that record instead of leaving the field out or guessing.",
    "Do not combine the signals into one score and do not name a winner.",
  ].join(" ");
}
