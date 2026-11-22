// Cache-first heads of the two ranked forecast views (perf pass, 3.3.0).
//
// The aggregate refresh already stores the exact head of both lists
// (`topHighest`, `topRising`, 100 ids each) using the same bounded getters the
// pages use, and the overview page already reads them. The priority views need
// the same head as display rows, so this module turns a *current* snapshot's
// ids back into hydrated items — the same fields, from the same point
// lookups — instead of re-sorting the eligible corpus per request.
//
// Correctness rests on three facts, each enforced here rather than assumed:
//   1. The stored head is a prefix of the full order, so its first N entries
//      equal what a live `getHighestForecast(db, N)` / `getRisingForecast(db,
//      undefined, N)` returns for N <= TOP_LIST_LIMIT (the getters' documented
//      full-order-then-slice contract).
//   2. A snapshot is only read through `readCurrentAggregates`, so a stale
//      generation can never label fresh provenance (the 3.2.0 freshness rule).
//   3. Hydration re-reads the live value for every displayed field (EPSS text,
//      KEV membership, primary CVSS, publication date), so no cached number is
//      rendered as current evidence — only the order comes from the cache.
//
// Anything the cache cannot answer exactly (a limit wider than the stored head,
// an unbounded request, no snapshot, a snapshot that is not current) returns
// null and the caller runs the live getter. There is no partial answer.

import type { CveDatabase } from "./db";
import { chunk } from "./db";
import { readCurrentAggregates, TOP_LIST_LIMIT } from "./aggregates";
import { hydrateOverviewItems, type PriorityItem, type RisingResult } from "./priority";

const HEAD_LOOKUP_CHUNK = 500;

function acceptsHead(limit: number | undefined): limit is number {
  return limit !== undefined && Number.isInteger(limit) && limit >= 0 && limit <= TOP_LIST_LIMIT;
}

/**
 * Publication dates for a pre-selected id set. The live getters read these from
 * the same join against `cve_records`; a bounded IN lookup returns the identical
 * value for every stored id (and nothing for an id that stopped being
 * published, which hydration then labels as unknown rather than inventing it).
 */
function publishedAtById(db: CveDatabase, ids: readonly string[]): Map<string, string | null> {
  const out = new Map<string, string | null>();
  for (const group of chunk(ids, HEAD_LOOKUP_CHUNK)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(
        `SELECT cve_id, date_published FROM cve_records WHERE state = 'PUBLISHED' AND cve_id IN (${placeholders})`,
      )
      .all(...group) as Array<{ cve_id: string; date_published: string | null }>;
    for (const row of rows) out.set(row.cve_id, row.date_published);
  }
  return out;
}

/**
 * Highest-forecast head from a current snapshot, or null when the cache cannot
 * answer this request exactly.
 */
export function readHighestForecastHead(db: CveDatabase, limit?: number): PriorityItem[] | null {
  if (!acceptsHead(limit)) return null;
  const { cached } = readCurrentAggregates(db);
  if (cached === null || cached.epssScoreDate === null) return null;
  const ids = cached.topHighest.slice(0, limit);
  const publishedAt = publishedAtById(db, ids);
  return hydrateOverviewItems(
    db,
    cached.epssScoreDate,
    ids.map((id) => ({ id, publishedAt: publishedAt.get(id) ?? null, epss: null })),
  );
}

/**
 * Rising-forecast head (ids plus exact delta strings) from a current snapshot,
 * or null when the cache cannot answer this request exactly.
 *
 * `deltaPp` is stored, not recomputed: the refresh wrote it with the same
 * `selectRisingForecast` call the live getter makes, so the displayed movement
 * is the exact stored decimal difference rather than a float re-derivation.
 */
export function readRisingForecastHead(
  db: CveDatabase,
  limit?: number,
): RisingResult<PriorityItem>[] | null {
  if (!acceptsHead(limit)) return null;
  const { cached } = readCurrentAggregates(db);
  if (cached === null || cached.epssScoreDate === null) return null;
  const head = cached.topRising.slice(0, limit);
  const publishedAt = publishedAtById(
    db,
    head.map((row) => row.id),
  );
  const items = hydrateOverviewItems(
    db,
    cached.epssScoreDate,
    head.map((row) => ({ id: row.id, publishedAt: publishedAt.get(row.id) ?? null, epss: null })),
  );
  const byId = new Map(items.map((item) => [item.id, item]));
  const results: RisingResult<PriorityItem>[] = [];
  for (const { id, deltaPp } of head) {
    const item = byId.get(id);
    if (item === undefined) continue;
    results.push({ item, deltaPp });
  }
  return results;
}
