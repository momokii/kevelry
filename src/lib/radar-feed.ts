// RSS 2.0 and Atom 1.0 serialization for the Change Radar feed (v3 epic E5).
// Pure formatting: no database, no Request, no network, so escaping and item
// mapping are testable without a server. The shared route supplies
// already-filtered events built from retained checkpoints and owns the
// HTTP/ETag layer.
//
// Nothing here writes prose about a change: an item is the event id, the
// before/after fields, the reason the diff recorded, and the source revision.

import { RADAR_RETENTION_DAYS } from "./radar";

/** The fields an RSS item needs; `RadarApiEvent` satisfies this shape. */
export interface RadarFeedEvent {
  eventId: string;
  observedAt: string;
  kind: string;
  cveId: string;
  changes: ReadonlyArray<{ field: string; before: string | null; after: string | null }>;
  sourceRevision: string;
  reason: string;
}

export interface RadarFeedMeta {
  /**
   * Absolute URL of this feed request, including its query, or null when the
   * public origin is unknown. Null omits `<atom:link rel="self">`: a relative
   * or bind-address link is worse than none for a subscriber.
   */
  feedUrl: string | null;
  /** Absolute URL of the JSON change feed with the same filters, or null. */
  jsonUrl: string | null;
  /** `observedAt` of the newest retained checkpoint, or null when none exist. */
  lastBuildAt: string | null;
  /** Earliest checkpoint date the retention window still allows (YYYY-MM-DD). */
  earliestAllowedDay: string;
  /**
   * True when the store holds at least one checkpoint. False makes the channel
   * description say the feed is not populated yet instead of letting a
   * subscriber infer "no changes" from an empty item list.
   */
  hasRetainedCheckpoints: boolean;
  retentionDays?: number;
}

const CVE_RECORD_BASE = "https://www.cve.org/CVERecord";

/** Atom 1.0 namespace, RFC 4287 §4.1.1. */
export const ATOM_NAMESPACE = "http://www.w3.org/2005/Atom";

/** Feed-level author name: the site, never a person (RFC 4287 §4.1.1). */
const FEED_AUTHOR_NAME = "Kevelry";

/**
 * Feed id used only when the public origin is unknown. RFC 4287 §4.2.6
 * requires an absolute IRI, so a relative path is not an option and the bind
 * address would be a lie; a fixed urn keeps the identifier permanent.
 */
const ATOM_FEED_FALLBACK_ID = "urn:cve-radar:feed:change-radar";

/**
 * Channel description for a store that has never retained a checkpoint. It
 * states the reason the item list is empty (the writer has not run yet) rather
 * than leaving "empty" to read as "no changes".
 */
const EMPTY_STATE_DESCRIPTION =
  "No change checkpoints are retained yet; this feed fills as the daily checkpoint writer runs.";

/** XML text escaping: `&` first so the introduced entities stay literal. */
export function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** RFC 822/1123 timestamp, or null when the input is not a parseable instant. */
export function rfc822Timestamp(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toUTCString();
}

/**
 * RFC 3339 timestamp (`Z` suffix), or null when the input is not a parseable
 * instant. Atom date constructs require RFC 3339 (§3.3), never RFC 822.
 */
export function rfc3339Timestamp(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

/**
 * Earliest checkpoint date the retention window allows, as a UTC day. A
 * checkpoint exactly `retentionDays` old is still retained; `isCheckpointExpired`
 * only drops ages strictly greater than the window.
 */
export function earliestAllowedCheckpointDate(
  asOf: Date,
  retentionDays: number = RADAR_RETENTION_DAYS,
): string {
  const dayStartMs = Date.UTC(asOf.getUTCFullYear(), asOf.getUTCMonth(), asOf.getUTCDate());
  return new Date(dayStartMs - retentionDays * 86_400_000).toISOString().slice(0, 10);
}

/** Description body: the factual diff, then the reason, then the source pin. */
function descriptionText(event: RadarFeedEvent): string {
  const lines = event.changes.map(
    (change) => `${change.field}: ${change.before ?? "null"} → ${change.after ?? "null"}`,
  );
  lines.push(`reason: ${event.reason}`);
  lines.push(`sourceRevision: ${event.sourceRevision}`);
  return lines.join("\n");
}

/**
 * Provenance text both formats publish: what the items are derived from, the
 * retention window, and (for an unpopulated store) why the item list is empty.
 * It never lets "empty" read as "nothing changed".
 */
function feedDescription(meta: RadarFeedMeta): string {
  const retentionDays = meta.retentionDays ?? RADAR_RETENTION_DAYS;
  const windowText = `${retentionDays}-day checkpoint retention window (earliest allowed checkpoint ${meta.earliestAllowedDay}). Reads never call upstream sources.`;
  return meta.hasRetainedCheckpoints
    ? `Accepted change events derived from local accepted daily CVE snapshots, limited to the ${windowText}`
    : `${EMPTY_STATE_DESCRIPTION} Limited to the ${windowText}`;
}

function itemXml(event: RadarFeedEvent): string {
  const lines = [
    "    <item>",
    `      <title>${escapeXml(`${event.cveId} — ${event.kind}`)}</title>`,
    `      <link>${escapeXml(`${CVE_RECORD_BASE}?id=${event.cveId}`)}</link>`,
    `      <guid isPermaLink="false">${escapeXml(event.eventId)}</guid>`,
  ];
  const pubDate = rfc822Timestamp(event.observedAt);
  if (pubDate !== null) lines.push(`      <pubDate>${pubDate}</pubDate>`);
  lines.push(`      <description>${escapeXml(descriptionText(event))}</description>`);
  lines.push("    </item>");
  return lines.join("\n");
}

/**
 * Serializes events (newest first, already limited by the route) into one RSS
 * 2.0 document. Channel metadata states the provenance the feed can promise:
 * accepted local snapshots, the retention window, and the newest checkpoint.
 */
export function buildRadarFeed(events: readonly RadarFeedEvent[], meta: RadarFeedMeta): string {
  const description = escapeXml(feedDescription(meta));
  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    "  <channel>",
    "    <title>CVE Change Radar change feed</title>",
  ];
  // The channel link and the Atom self link are absolute URLs. When the public
  // origin is unknown the resolver says so; omitting them beats publishing the
  // `0.0.0.0` bind address under which the standalone server answers.
  if (meta.jsonUrl !== null) lines.push(`    <link>${escapeXml(meta.jsonUrl)}</link>`);
  lines.push(
    `    <description>${description}</description>`,
    "    <language>en</language>",
    "    <generator>CVE Change Radar v1</generator>",
  );
  if (meta.feedUrl !== null) {
    lines.push(
      `    <atom:link href="${escapeXml(meta.feedUrl)}" rel="self" type="application/rss+xml"/>`,
    );
  }
  const lastBuildDate = rfc822Timestamp(meta.lastBuildAt);
  if (lastBuildDate !== null) lines.push(`    <lastBuildDate>${lastBuildDate}</lastBuildDate>`);
  for (const event of events) lines.push(itemXml(event));
  lines.push("  </channel>", "</rss>");
  return `${lines.join("\n")}\n`;
}

/**
 * One Atom entry: the same fields as the RSS item (so consumers can match
 * formats by id), rendered as RFC 4287 elements. `id` is the `eventId` the
 * RSS `<guid>` uses, `updated` is the checkpoint instant in RFC 3339, and the
 * summary is the escaped diff/reason/revision text. The fallback instant only
 * fires for a stored timestamp this process cannot parse, which would
 * otherwise make the document invalid (§4.1.2 requires atom:updated).
 */
function atomEntryXml(event: RadarFeedEvent, fallbackUpdated: string): string {
  const updated = rfc3339Timestamp(event.observedAt) ?? fallbackUpdated;
  return [
    "  <entry>",
    `    <id>${escapeXml(event.eventId)}</id>`,
    `    <title type="text">${escapeXml(`${event.cveId} — ${event.kind}`)}</title>`,
    `    <link rel="alternate" type="text/html" href="${escapeXml(
      `${CVE_RECORD_BASE}?id=${event.cveId}`,
    )}"/>`,
    `    <updated>${updated}</updated>`,
    `    <summary type="text">${escapeXml(descriptionText(event))}</summary>`,
    "  </entry>",
  ].join("\n");
}

/**
 * Serializes the same events as `buildRadarFeed` into one RFC 4287 Atom 1.0
 * document. Feed-level requirements are all present: `id` (the feed's own
 * absolute URL, or a fixed urn when the public origin is unknown), `title`,
 * `subtitle`, `updated` (newest checkpoint, RFC 3339), and one `author` with a
 * name so entries need none. `rel="self"` and `rel="alternate"` are omitted
 * together when `resolvePublicBaseUrl` reports no usable public origin, exactly
 * like the RSS channel and atom:link are.
 */
export function buildRadarAtomFeed(events: readonly RadarFeedEvent[], meta: RadarFeedMeta): string {
  // A store with no retained checkpoint still needs a valid atom:updated. The
  // retention window start is deterministic and cannot claim freshness.
  const feedUpdated =
    rfc3339Timestamp(meta.lastBuildAt) ?? `${meta.earliestAllowedDay}T00:00:00.000Z`;
  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<feed xmlns="${ATOM_NAMESPACE}">`,
    `  <id>${escapeXml(meta.feedUrl ?? ATOM_FEED_FALLBACK_ID)}</id>`,
    '  <title type="text">CVE Change Radar change feed</title>',
    `  <subtitle type="text">${escapeXml(feedDescription(meta))}</subtitle>`,
    `  <updated>${feedUpdated}</updated>`,
    "  <author>",
    `    <name>${escapeXml(FEED_AUTHOR_NAME)}</name>`,
    "  </author>",
  ];
  if (meta.feedUrl !== null) {
    lines.push(
      `  <link rel="self" type="application/atom+xml" href="${escapeXml(meta.feedUrl)}"/>`,
    );
  }
  if (meta.jsonUrl !== null) {
    lines.push(
      `  <link rel="alternate" type="application/json" href="${escapeXml(meta.jsonUrl)}"/>`,
    );
  }
  lines.push("  <generator>CVE Change Radar v1</generator>");
  for (const event of events) lines.push(atomEntryXml(event, feedUpdated));
  lines.push("</feed>");
  return `${lines.join("\n")}\n`;
}
