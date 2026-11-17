// CWE names in the relation graph (v3 E3). Seeds the dev server's corpus under
// .e2e/ with a deterministic invented corpus plus a fixture MITRE catalog: one
// `known` id the graph's shared-CWE groups render, and one id absent from the
// catalog. Each test deploys the catalog state it asserts, and the baseline is
// restored afterwards so the next spec starts from the same rows.
// Serial: every test shares the one server corpus and swaps its catalog state.

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

import { openDatabase, type CveDatabase } from "../../src/lib/db";
import { deployE2eCorpus, resetToBaseline } from "./corpus";

test.describe.configure({ mode: "serial" });

const STAMP = "2026-10-24T00:00:00.000Z";
const CWE_VERSION = "1000-2";

const CENTER = "CVE-2099-8001";
const KNOWN_ID = "CWE-416";
const KNOWN_NAME = "Use After Free";
const UNMAPPED_ID = "CWE-999999";

interface RecordFixture {
  cveId: string;
  title: string;
  vendor: string;
  cwes: string[];
}

// Every shared attribute below is real: 8001/8002 share the catalog CWE,
// 8001/8003 share the uncatalogued id, and the vendor label groups 8001/8002.
const FIXTURES: RecordFixture[] = [
  {
    cveId: CENTER,
    title: "Use-after-free in the demo renderer.",
    vendor: "Acme",
    cwes: [KNOWN_ID, UNMAPPED_ID],
  },
  {
    cveId: "CVE-2099-8002",
    title: "Freed renderer handle reused by the compositor.",
    vendor: "Acme",
    cwes: [KNOWN_ID],
  },
  {
    cveId: "CVE-2099-8003",
    title: "Imported record waiting on an uncatalogued weakness class.",
    vendor: "Other",
    cwes: [UNMAPPED_ID],
  },
];

const tempDirs: string[] = [];
let readyCatalogDb = "";
let emptyCatalogDb = "";

async function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}

function dayAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
}

function seedCorpus(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    const record = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
        "title, description, description_lang, source_revision, created_at, updated_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    const kev = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, due_date, recorded_at) " +
        "VALUES (?, ?, ?, ?, ?, ?)",
    );
    const kevCwe = db.handle.prepare("INSERT INTO kev_cwes (cve_id, cwe_id) VALUES (?, ?)");
    for (const fixture of FIXTURES) {
      record.run(
        fixture.cveId,
        "5.1",
        "PUBLISHED",
        `${dayAgo(4)}T00:00:00.000Z`,
        `${dayAgo(4)}T00:00:00.000Z`,
        fixture.title,
        `Supplied description for ${fixture.cveId}; the graph links its CWE ids.`,
        "en",
        "rev-graph-cwe",
        STAMP,
        STAMP,
      );
      kev.run(fixture.cveId, dayAgo(2), STAMP, fixture.vendor, dayAgo(-10), STAMP);
      for (const cwe of fixture.cwes) kevCwe.run(fixture.cveId, cwe);
    }
    const sync = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    sync.run("cve", STAMP, STAMP, "succeeded", "graph-cwe-cve", "hash-cve", null);
    sync.run("kev", STAMP, STAMP, "succeeded", "graph-cwe-kev", "hash-kev", null);
  });
}

function seedReadyCatalog(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO cwe_catalog_meta (id, version, source, source_hash, retrieved_at, status, record_count, notes) " +
          "VALUES (1, ?, 'MITRE CWE', ?, ?, 'ready', 1, NULL)",
      )
      .run(CWE_VERSION, "c".repeat(64), STAMP);
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO cwe_entries (cwe_id, name, abstraction, status, summary, mitigation, version, updated_at) " +
          "VALUES (?, ?, 'Class', 'Stable', ?, NULL, ?, ?)",
      )
      .run(
        KNOWN_ID,
        KNOWN_NAME,
        "The product reuses memory after it has been freed.",
        CWE_VERSION,
        STAMP,
      );
  });
}

function buildDbFile(withCatalog: boolean): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-graph-cwe-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  seedCorpus(db);
  if (withCatalog) seedReadyCatalog(db);
  db.close();
  return path.join(dir, "cve.db");
}

test.beforeAll(() => {
  readyCatalogDb = buildDbFile(true);
  emptyCatalogDb = buildDbFile(false);
});

test.afterAll(() => {
  resetToBaseline();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

test("a known shared CWE shows its id and published name, linked to MITRE", async ({ page }) => {
  deployE2eCorpus(readyCatalogDb);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`/graph?focus=${CENTER}`);
  await expect(page.getByTestId("graph-centered")).toBeVisible();

  const group = page.getByTestId(`graph-group-cwe-${KNOWN_ID}`);
  await expect(group).toBeVisible();
  const chip = group.getByTestId("graph-cwe-chip");
  await expect(chip.getByTestId("graph-cwe-id")).toHaveText(KNOWN_ID);
  await expect(chip.getByTestId("graph-cwe-name")).toHaveText(`· ${KNOWN_NAME}`);

  // The whole chip is the link, canonical and safe to open in a new tab.
  await expect(chip).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/416.html");
  await expect(chip).toHaveAttribute("target", "_blank");
  const rel = (await chip.getAttribute("rel")) ?? "";
  expect(rel.split(" ").sort()).toEqual(["noopener", "noreferrer"]);

  // 44px target, and the id is not the part that ellipsizes.
  const box = await chip.boundingBox();
  expect(box, "chip has a box").not.toBeNull();
  expect((box as { height: number }).height).toBeGreaterThanOrEqual(44);
  const nameStyle = await chip
    .getByTestId("graph-cwe-name")
    .evaluate((el) => getComputedStyle(el).textOverflow);
  expect(nameStyle).toBe("ellipsis");

  // A CWE id is a weakness class, not a severity: no band colouring or wording.
  await expect(chip.locator("[class*='badge']")).toHaveCount(0);
  await expect(group).not.toContainText(/critical|severity|vulnerable to/i);
  // A loaded catalog is not "unavailable".
  await expect(page.getByTestId("graph-cwe-taxonomy")).toHaveCount(0);
});

test("an id absent from the catalog keeps its id and says so", async ({ page }) => {
  deployE2eCorpus(readyCatalogDb);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`/graph?focus=${CENTER}`);
  await expect(page.getByTestId("graph-centered")).toBeVisible();

  const group = page.getByTestId(`graph-group-cwe-${UNMAPPED_ID}`);
  await expect(group).toBeVisible();
  const chip = group.getByTestId("graph-cwe-chip");
  await expect(chip).toHaveAttribute("data-cwe-state", "unmapped");
  await expect(chip.getByTestId("graph-cwe-id")).toHaveText(UNMAPPED_ID);
  await expect(chip.getByTestId("graph-cwe-state")).toHaveText("not in the loaded catalog");
  // No invented name, but the well-formed id keeps its canonical page.
  await expect(chip.getByTestId("graph-cwe-name")).toHaveCount(0);
  await expect(chip).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/999999.html");
});

test("an empty catalog says taxonomy unavailable once and keeps every id", async ({ page }) => {
  deployE2eCorpus(emptyCatalogDb);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`/graph?focus=${CENTER}`);
  await expect(page.getByTestId("graph-centered")).toBeVisible();

  // One statement for the view, not one per chip.
  await expect(page.getByTestId("graph-cwe-taxonomy")).toHaveCount(1);
  await expect(page.getByTestId("graph-cwe-taxonomy")).toHaveText("taxonomy unavailable");

  const chips = page.locator(
    "[data-testid='graph-cwe-chip'][data-cwe-state='taxonomy-unavailable']",
  );
  await expect(chips).toHaveCount(2);
  await expect(chips.nth(0).getByTestId("graph-cwe-id")).toHaveText(KNOWN_ID);
  await expect(chips.nth(1).getByTestId("graph-cwe-id")).toHaveText(UNMAPPED_ID);
  // No name is claimed, and the unmapped wording is not used while the whole
  // catalog is missing.
  await expect(page.getByTestId("graph-cwe-name")).toHaveCount(0);
  await expect(page.locator("[data-cwe-state='unmapped']")).toHaveCount(0);
});

test("the labeled graph fits 360px without horizontal overflow", async ({ page }) => {
  deployE2eCorpus(readyCatalogDb);
  await page.setViewportSize({ width: 360, height: 800 });
  await page.goto(`/graph?focus=${CENTER}`);
  await expect(page.getByTestId("graph-centered")).toBeVisible();
  await expect(page.getByTestId(`graph-group-cwe-${KNOWN_ID}`)).toBeVisible();
  // The shell chrome accounts for the repo-wide 1px tolerance at 360px
  // (see tests/e2e/ui-foundation.spec.ts); the graph adds none of its own.
  expect(await horizontalOverflow(page)).toBeLessThanOrEqual(1);
});
