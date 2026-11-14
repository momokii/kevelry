// RSS 2.0 serialization for the Change Radar feed (v3 epic E5). Pure
// formatting: no database, no Request, no network, so escaping and item
// mapping are testable without a server. The route supplies already-filtered
// events built from retained checkpoints and owns the HTTP/ETag layer.
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
  /** Absolute URL of this feed request, including its query. */
  feedUrl: string;
  /** Absolute URL of the JSON change feed with the same filters. */
  jsonUrl: string;
  /** `observedAt` of the newest retained checkpoint, or null when none exist. */
  lastBuildAt: string | null;
  /** Earliest checkpoint date the retention window still allows (YYYY-MM-DD). */
  earliestAllowedDay: string;
  retentionDays?: number;
}

const CVE_RECORD_BASE = "https://www.cve.org/CVERecord";

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
  const retentionDays = meta.retentionDays ?? RADAR_RETENTION_DAYS;
  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    "  <channel>",
    "    <title>CVE Change Radar change feed</title>",
    `    <link>${escapeXml(meta.jsonUrl)}</link>`,
    `    <description>Accepted change events derived from local accepted daily CVE snapshots, limited to the ${retentionDays}-day checkpoint retention window (earliest allowed checkpoint ${escapeXml(meta.earliestAllowedDay)}). Reads never call upstream sources.</description>`,
    "    <language>en</language>",
    "    <generator>CVE Change Radar v1</generator>",
    `    <atom:link href="${escapeXml(meta.feedUrl)}" rel="self" type="application/rss+xml"/>`,
  ];
  const lastBuildDate = rfc822Timestamp(meta.lastBuildAt);
  if (lastBuildDate !== null) lines.push(`    <lastBuildDate>${lastBuildDate}</lastBuildDate>`);
  for (const event of events) lines.push(itemXml(event));
  lines.push("  </channel>", "</rss>");
  return `${lines.join("\n")}\n`;
}
