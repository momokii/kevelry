import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  importSsvcFromCheckout,
  listSsvcFiles,
  parseSsvcRecord,
  SsvcImportError,
} from "../src/lib/ssvc-import";

const STAMP = "2026-11-01T00:00:00.000Z";

function makeDb(): { db: CveDatabase; dir: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-ssvc-"));
  return { db: openDatabase({ dataDir: dir }), dir };
}

const dirs: string[] = [];
const dbs: CveDatabase[] = [];
afterEach(() => {
  while (dbs.length > 0) {
    try {
      (dbs.pop() as CveDatabase).close();
    } catch {
      // best effort
    }
  }
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

function record(ssvc?: { exploitation: string; automatable: string; impact: string }): unknown {
  const adp: unknown[] = [{ title: "CVE Program Container", providerMetadata: {} }];
  if (ssvc !== undefined) {
    adp.push({
      title: "CISA ADP Vulnrichment",
      metrics: [
        {
          other: {
            type: "ssvc",
            content: {
              id: "CVE-2099-0001",
              role: "CISA Coordinator",
              version: "2.0.3",
              timestamp: "2025-02-04T14:25:34.416117Z",
              options: [
                { Exploitation: ssvc.exploitation },
                { Automatable: ssvc.automatable },
                { "Technical Impact": ssvc.impact },
              ],
            },
          },
        },
      ],
    });
  }
  return { dataType: "CVE_RECORD", containers: { cna: {}, adp } };
}

describe("vulnrichment SSVC parsing", () => {
  it("reads the three published decision points verbatim", () => {
    const parsed = parseSsvcRecord(
      record({ exploitation: "active", automatable: "yes", impact: "total" }),
    );
    expect(parsed).toEqual({
      exploitation: "active",
      automatable: "yes",
      technicalImpact: "total",
      version: "2.0.3",
      timestamp: "2025-02-04T14:25:34.416117Z",
    });
  });

  it("returns null when the record publishes no SSVC block", () => {
    expect(parseSsvcRecord(record())).toBeNull();
    expect(parseSsvcRecord({ containers: { adp: [] } })).toBeNull();
  });

  it("rejects a block that is present but malformed or unknown", () => {
    expect(() =>
      parseSsvcRecord(record({ exploitation: "maybe", automatable: "yes", impact: "total" })),
    ).toThrowError(SsvcImportError);
    expect(() =>
      parseSsvcRecord(record({ exploitation: "none", automatable: "yes", impact: "partial" })),
    ).not.toThrow();
  });
});

describe("ssvc checkout import", () => {
  function writeRecord(
    root: string,
    year: string,
    bucket: string,
    id: string,
    body: unknown,
  ): void {
    const dir = path.join(root, year, bucket);
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(body), "utf8");
  }

  it("reads only wanted ids, replaces rows, and counts absent records", () => {
    const { db, dir } = makeDb();
    dbs.push(db);
    const root = mkdtempSync(path.join(tmpdir(), "cve-ssvc-repo-"));
    dirs.push(root);
    writeRecord(
      root,
      "2024",
      "21xxx",
      "CVE-2099-0001",
      record({
        exploitation: "active",
        automatable: "yes",
        impact: "total",
      }),
    );
    writeRecord(root, "2024", "21xxx", "CVE-2099-0002", record());
    writeRecord(
      root,
      "2024",
      "21xxx",
      "CVE-2099-0003",
      record({
        exploitation: "poc",
        automatable: "no",
        impact: "partial",
      }),
    );

    const wanted = new Set(["CVE-2099-0001", "CVE-2099-0002"]);
    const files = listSsvcFiles(root, wanted);
    expect(files.sort()).toEqual([
      "2024/21xxx/CVE-2099-0001.json",
      "2024/21xxx/CVE-2099-0002.json",
    ]);

    const result = importSsvcFromCheckout(db, {
      checkoutDir: root,
      wanted,
      revision: "rev-1",
      now: STAMP,
    });
    expect(result).toMatchObject({ ok: true, total: 2, parsed: 1, absent: 1, invalid: [] });

    const rows = db.handle
      .prepare("SELECT cve_id, exploitation, automatable, technical_impact FROM ssvc_records")
      .all();
    expect(rows).toEqual([
      {
        cve_id: "CVE-2099-0001",
        exploitation: "active",
        automatable: "yes",
        technical_impact: "total",
      },
    ]);

    // A later cycle that no longer carries the block drops the row.
    writeRecord(root, "2024", "21xxx", "CVE-2099-0001", record());
    const second = importSsvcFromCheckout(db, { checkoutDir: root, wanted, now: STAMP });
    expect(second.parsed).toBe(0);
    expect(db.handle.prepare("SELECT COUNT(*) AS n FROM ssvc_records").get()).toEqual({ n: 0 });
  });

  it("reports unreadable records instead of aborting the cycle", () => {
    const { db } = makeDb();
    dbs.push(db);
    const root = mkdtempSync(path.join(tmpdir(), "cve-ssvc-bad-"));
    dirs.push(root);
    const badDir = path.join(root, "2024", "21xxx");
    mkdirSync(badDir, { recursive: true });
    writeFileSync(path.join(badDir, "CVE-2099-0001.json"), "{not json", "utf8");
    const result = importSsvcFromCheckout(db, {
      checkoutDir: root,
      wanted: new Set(["CVE-2099-0001"]),
      now: STAMP,
    });
    expect(result.invalid).toEqual(["CVE-2099-0001"]);
    expect(result.parsed).toBe(0);
  });
});
