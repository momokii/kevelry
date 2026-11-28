// The turn's evidence: everything a reader may be told the server actually read.
//
// "Citations are server data" is this product's central claim, so it needs one
// home rather than a closure set mutated inside a generator. This is that home.
// It reads the readings a turn produced — one entry per executed tool call — and
// the prose the reader was given, and returns four lists:
//
//   citationIds        ids a tool payload contained. Never an id the model
//                      claimed: a hallucinated id cannot become a chip.
//   unverifiedIds      ids the prose named that no payload contained. Reported,
//                      never used to edit the answer — the reader sees the doubt
//                      instead of losing the sentence.
//   unverifiedNumbers  figures the prose printed that no payload supports, as
//                      printed. Empty when the turn read nothing, because with
//                      nothing to compare against a figure is unchecked, not
//                      doubtful. "Payload" here is the tool outcome whole: its
//                      `data` and the metadata an answer may cite — the day it
//                      was read, the snapshot and version behind it, the window
//                      it covers. A true sentence that quotes a tool's own
//                      `retrievedAt` must not be accused.
//   webSources         hosts a successful fetch actually read, one per distinct
//                      URL. The server is the authority on which host answered.
//
// Pure by construction: no I/O, no clock, no random, no SSE. Given the same
// readings and the same prose it returns the same evidence, which is what lets
// these rules be tested without a provider.

import { CVE_ID_RE } from "../cve-id";
import { unverifiedAnswerNumbers } from "./numbers";
import type { ToolOutcome } from "./tools";

/** Upper bound on citation ids one turn may report. */
export const ASSISTANT_CITATION_CAP = 200;

/**
 * Payload keys whose ids are not evidence: `get_cves` reports the ids this
 * dataset holds no record for in `missing`, and an id that was asked for and
 * not found must never be cited as a record the turn read.
 */
const NON_EVIDENCE_KEYS = new Set(["missing"]);

/**
 * Ids the server actually read, from any tool payload shape.
 *
 * Deliberately generic: every tool nests ids differently (`items[].cveId`,
 * `record.cveId`, `points[]` for history), and a per-tool extractor would be a
 * second place to forget when a tool is added. Only strings matching the id
 * shape are collected, depth- and count-bounded so a hostile payload cannot
 * turn this into a walk of a huge object graph. A key named `missing` is
 * skipped whole: an id that was asked for and not found is not a citation.
 */
export function collectRecordIds(value: unknown): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  const walk = (node: unknown, depth: number): void => {
    if (found.length >= ASSISTANT_CITATION_CAP || depth > 6) return;
    if (typeof node === "string") {
      if (CVE_ID_RE.test(node) && !seen.has(node)) {
        seen.add(node);
        found.push(node);
      }
      return;
    }
    if (Array.isArray(node)) {
      for (const entry of node) walk(entry, depth + 1);
      return;
    }
    if (typeof node === "object" && node !== null) {
      for (const [key, entry] of Object.entries(node)) {
        if (NON_EVIDENCE_KEYS.has(key)) continue;
        walk(entry, depth + 1);
      }
    }
  };
  walk(value, 0);
  return found;
}

/**
 * CVE ids as they appear in prose: case-insensitive, so a model that writes
 * `cve-2021-44228` is still checked rather than slipping past the classifier.
 */
const ANSWER_ID_PATTERN = /\bCVE-\d{4}-\d{4,}\b/gi;

/**
 * Every record id the answer text names, deduplicated and case-normalised.
 *
 * This is the prose side of the provenance rule: `collectRecordIds` walks what a
 * tool returned, this walks what the reader was told. It is a separate walk on
 * purpose — the answer is a string, not a payload, and a single regex is the
 * whole extraction rule.
 */
export function extractAnswerIds(text: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  for (const match of text.matchAll(ANSWER_ID_PATTERN)) {
    const id = match[0].toUpperCase();
    if (seen.has(id)) continue;
    seen.add(id);
    found.push(id);
  }
  return found;
}

/**
 * Ids in the prose that no tool payload in this turn contained.
 *
 * `verified` is the set the turn already collected from tool results — the same
 * set `citations` reports — so a citation and a verified id cannot disagree.
 * The list is complete rather than sampled: the answer is bounded by the model's
 * token cap, and a dropped id would be exactly the silent omission this check
 * exists to prevent.
 */
export function unverifiedAnswerIds(text: string, verified: ReadonlySet<string>): string[] {
  return extractAnswerIds(text).filter((id) => !verified.has(id));
}

/** One host a successful fetch read, as the citation area's web chip reports it. */
export interface WebSource {
  url: string;
  host: string;
}

/**
 * The host a successful web fetch read, for the citation area's chip.
 *
 * The server, not the client, is the authority on which host answered: the URL
 * the model asked for can differ from the one that was read when a single
 * allow-listed redirect was followed. Anything but a successful fetch yields
 * nothing, so a refused URL never becomes a chip.
 */
export function webEvidence(name: string, outcome: ToolOutcome): WebSource | null {
  if (name !== "fetch_authoritative" || !outcome.ok) return null;
  const data: unknown = outcome.data;
  if (typeof data !== "object" || data === null) return null;
  const { url, host } = data as { url?: unknown; host?: unknown };
  if (typeof url !== "string" || typeof host !== "string") return null;
  return { url, host };
}

/**
 * Outcome keys outside `data` whose values an answer may legitimately cite.
 *
 * A list, not "every key but `data`": `rows`, `tool` and a call's bookkeeping
 * describe the call, not the corpus, and a haystack that swallowed them would
 * let an incidental number excuse a figure the prose invented. These are the
 * keys a reader would accept as provenance for what the answer prints — when it
 * was read, which snapshot or model produced it, and the window it covers.
 *
 * Every entry answers a specific way an honest answer was accused: a model that
 * wrote "read 2026-11-28" was quoting a tool's `retrievedAt`, which only `data`
 * never carried. It is spelled out so adding a tool means reading this list, not
 * hoping a generic walk happens to find the value.
 *
 * The list accepts a false negative to remove a false positive: `retrievedAt` is
 * "now", so a fabricated day that happens to be today would verify, and a window
 * makes every day inside it citable. That is the cheaper error — a caution that
 * fires on a true sentence teaches the reader to ignore the caution entirely.
 */
const CITABLE_METADATA_KEYS: ReadonlySet<string> = new Set([
  "retrievedAt",
  "generatedAt",
  "computedAt",
  "fetchedAt",
  "asOf",
  "asOfDate",
  "version",
  "modelVersion",
  "catalogVersion",
  "datasetVersion",
  "kevVersion",
  "window",
  "dateRange",
  "windowStart",
  "windowEnd",
]);

/** Upper bound on metadata scalars one turn may add, for a wide date window. */
const CITABLE_METADATA_CAP = 256;

/** Strings and numbers under one metadata value, at any depth, count-bounded. */
function collectMetadataScalars(node: unknown, into: unknown[], depth: number): void {
  if (into.length >= CITABLE_METADATA_CAP || depth > 6) return;
  if (typeof node === "string" || typeof node === "number") {
    into.push(node);
    return;
  }
  if (Array.isArray(node)) {
    for (const entry of node) collectMetadataScalars(entry, into, depth + 1);
    return;
  }
  if (typeof node === "object" && node !== null) {
    for (const entry of Object.values(node)) collectMetadataScalars(entry, into, depth + 1);
  }
}

/**
 * The metadata scalars one successful outcome lets an answer cite.
 *
 * Only the keys above, matched at any depth (`retrievedAt`, or
 * `meta.asOf.date`), and only strings and numbers, because those are the shapes
 * a figure can be printed from. `data` is not descended into: it is handed to
 * the haystack whole, so walking it again would only spend the cap.
 */
export function collectCitableMetadata(outcome: unknown): unknown[] {
  const found: unknown[] = [];
  const walk = (node: unknown, depth: number): void => {
    if (found.length >= CITABLE_METADATA_CAP || depth > 6) return;
    if (Array.isArray(node)) {
      for (const entry of node) walk(entry, depth + 1);
      return;
    }
    if (typeof node !== "object" || node === null) return;
    for (const [key, entry] of Object.entries(node)) {
      if (key === "data") continue;
      if (CITABLE_METADATA_KEYS.has(key)) collectMetadataScalars(entry, found, depth + 1);
      else walk(entry, depth + 1);
    }
  };
  walk(outcome, 0);
  return found;
}

/**
 * One tool call the turn executed, as evidence reads it.
 *
 * The name is what the model asked for and the outcome is what the dispatcher
 * produced — a failure included, because a failure is a fact about the turn even
 * though it is not evidence: its reason names no figure and returns no id.
 */
export interface ToolReading {
  name: string;
  outcome: ToolOutcome;
}

/** Everything one turn can honestly say its tools returned. */
export interface TurnEvidence {
  citationIds: string[];
  unverifiedIds: string[];
  unverifiedNumbers: string[];
  webSources: WebSource[];
}

export interface EvidenceInput {
  /** Every call the turn executed, in the order it ran them. */
  toolCalls: readonly ToolReading[];
  /** The prose the reader received this turn, every delta in order. */
  answerText: string;
  /**
   * The turn's one-fetch allowance, read but never spent here.
   *
   * It is the authority on whether this turn was allowed to read the web at all:
   * a source is counted only when the allowance was actually spent. Absent means
   * the caller keeps no budget, and the successful fetch is evidence on its own.
   */
  webBudget?: { used: boolean };
}

/**
 * The turn's evidence, from its readings and its prose.
 *
 * One pass over the calls: each successful result contributes its ids and its
 * payload — the payload whole, because a figure has to be compared with the
 * value the tool returned, not with a summary of it — plus the metadata scalars
 * `collectCitableMetadata` names, and each successful fetch contributes its
 * host, deduplicated by URL. Order is the turn's own: first appearance across
 * the calls, which is the order the reader watched them run.
 *
 * A failed call contributes nothing but its name: only a successful result is
 * evidence.
 */
export function collectEvidence({ toolCalls, answerText, webBudget }: EvidenceInput): TurnEvidence {
  const verified = new Set<string>();
  const payloads: unknown[] = [];
  const webSources: WebSource[] = [];
  const seenUrls = new Set<string>();

  for (const { name, outcome } of toolCalls) {
    if (outcome.ok) {
      for (const id of collectRecordIds(outcome.data)) verified.add(id);
      payloads.push(outcome.data, ...collectCitableMetadata(outcome));
    }
    const web = webEvidence(name, outcome);
    if (web === null || seenUrls.has(web.url)) continue;
    if (webBudget !== undefined && !webBudget.used) continue;
    seenUrls.add(web.url);
    webSources.push(web);
  }

  return {
    citationIds: [...verified],
    unverifiedIds: unverifiedAnswerIds(answerText, verified),
    unverifiedNumbers: unverifiedAnswerNumbers(answerText, payloads),
    webSources,
  };
}
