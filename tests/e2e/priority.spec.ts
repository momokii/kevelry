// Priority views journey (plan todo 20). Seeds the dev server's DATA_DIR with
// a deterministic invented corpus (CVE-2099 IDs, relative dates so the suite
// stays green over time), then asserts each of the four named modes renders
// the exact service order with ordering inputs, score dates/models, coverage
// denominators, and a methodology link beside the list. Expected orders are
// computed with the real priority services against a temp-DATA_DIR mirror of
// the same fixtures — rendered order must match service fixtures 1:1.
// Unknown and stale values stay labeled in place, never zeroed or hidden.
// Serial: every test shares the one server DATA_DIR.

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";

import { openDatabase, type CveDatabase } from "../../src/lib/db";
import {
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "../../src/lib/priority";

const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-20-cve-change-radar";

const MODEL = "v2026.06.15";
const IDS = [
  "CVE-2099-1001",
  "CVE-2099-1002",
  "CVE-2099-1003",
  "CVE-2099-1004",
  "CVE-2099-1005",
  "CVE-2099-1006",
  "CVE-2099-1007",
  "CVE-2099-1008",
] as const;

function day(offsetDays: number): string {
  return new Date(Date.now() + offsetDays * 86_400_000).toISOString().slice(0, 10);
}

function serverDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") {
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
  }
  return path.join(process.cwd(), "data");
}

function wipeFixtures(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    const placeholders = IDS.map(() => "?").join(", ");
    db.handle.prepare(`DELETE FROM epss_daily WHERE cve_id IN (${placeholders})`).run(...IDS);
    db.handle.prepare(`DELETE FROM cvss_metrics WHERE cve_id IN (${placeholders})`).run(...IDS);
    db.handle.prepare(`DELETE FROM kev_entries WHERE cve_id IN (${placeholders})`).run(...IDS);
    db.handle.prepare(`DELETE FROM cve_records WHERE cve_id IN (${placeholders})`).run(...IDS);
    db.handle
      .prepare("DELETE FROM sync_runs WHERE revision LIKE ?")
      .run("priority-e2e-%");
  });
}

function seedPriorityFixtures(db: CveDatabase, scoreDate: string, prevDate: string): void {
  const nowIso = new Date().toISOString();
  wipeFixtures(db);
  db.runBoundedWrite(() => {
    const record = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    const pub = (offset: number | null) =>
      offset === null ? null : `${day(offset)}T00:00:00.000Z`;
    record.run(IDS[0], "5.1", "PUBLISHED", pub(-4), "Supplied CNA title: overflow in demo service.", "Supplied description for CVE-2099-1001 with enough detail to render an excerpt.", "en", nowIso, nowIso);
    record.run(IDS[1], "5.1", "PUBLISHED", pub(-2), "Supplied CNA title: privilege escalation in demo panel.", "Supplied description for CVE-2099-1002 with enough detail to render an excerpt.", "en", nowIso, nowIso);
    record.run(IDS[2], "5.1", "PUBLISHED", pub(-14), "Supplied CNA title: parser flaw in demo library.", "Supplied description for CVE-2099-1003 with enough detail to render an excerpt.", "en", nowIso, nowIso);
    record.run(IDS[3], "5.1", "PUBLISHED", pub(-5), null, "", null, nowIso, nowIso);
    record.run(IDS[4], "5.1", "PUBLISHED", pub(-60), "Supplied CNA title: old flaw outside the window.", "Supplied description for CVE-2099-1005; high severity but published outside the 30-day window.", "en", nowIso, nowIso);
    record.run(IDS[5], "5.1", "PUBLISHED", null, null, "Supplied description for CVE-2099-1006 with an unknown publication date.", "en", nowIso, nowIso);
    record.run(IDS[6], "5.1", "REJECTED", pub(-2), null, "Rejected record: not a vulnerability.", "en", nowIso, nowIso);
    record.run(IDS[7], "5.1", "PUBLISHED", pub(-3), "Supplied CNA title: ADP-only scored demo flaw.", "Supplied description for CVE-2099-1008; ADP-only metrics are secondary, never promoted.", "en", nowIso, nowIso);

    const kev = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
    );
    kev.run(IDS[0], day(-2), nowIso, nowIso);
    kev.run(IDS[1], day(-1), nowIso, nowIso);
    kev.run(IDS[3], day(-3), nowIso, nowIso);
    kev.run(IDS[6], day(-1), nowIso, nowIso);

    const epss = db.handle.prepare(
      "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
    );
    const both = (id: string, prev: string, cur: string, model: string = MODEL) => {
      epss.run(id, prevDate, model, prev, "0.80000");
      epss.run(id, scoreDate, model, cur, "0.80000");
    };
    both(IDS[0], "0.10", "0.18");
    both(IDS[1], "0.20", "0.28");
    both(IDS[2], "0.90", "0.90");
    both(IDS[4], "0.04", "0.05");
    both(IDS[5], "0.40", "0.40");
    epss.run(IDS[6], scoreDate, MODEL, "0.99", "0.99000");
    epss.run(IDS[7], prevDate, "model-a", "0.10", "0.50000");
    epss.run(IDS[7], scoreDate, "model-b", "0.50", "0.85000");

    const cvss = db.handle.prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
    );
    cvss.run(IDS[0], "CNA", "3.1", "9.8", "CVSS:3.1/AV:N", 0);
    cvss.run(IDS[1], "CNA", "3.1", "9.1", "CVSS:3.1/AV:N", 0);
    cvss.run(IDS[2], "CNA", "4.0", "8.5", "CVSS:4.0/AV:N", 0);
    cvss.run(IDS[3], "CNA", "3.1", "7.5", "CVSS:3.1/AV:N", 0);
    cvss.run(IDS[4], "CNA", "3.1", "9.8", "CVSS:3.1/AV:N", 0);
    cvss.run(IDS[6], "CNA", "3.1", "10.0", "CVSS:3.1/AV:N", 0);
    cvss.run(IDS[7], "ADP", "4.0", "10.0", "CVSS:4.0/AV:N", 0);

    const sync = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    sync.run("cve", nowIso, nowIso, "succeeded", "priority-e2e-cve", "hash-cve", null);
    sync.run("kev", nowIso, nowIso, "succeeded", "priority-e2e-kev", "hash-kev", null);
    sync.run("epss", nowIso, nowIso, "succeeded", `priority-e2e-epss@${scoreDate}@${MODEL}`, "hash-epss", null);
  });
}

interface ExpectedOrders {
  knownExploited: string[];
  highestForecast: string[];
  newCritical: string[];
  risingForecast: string[];
  risingDeltas: string[];
}

function expectedFromServices(scoreDate: string, prevDate: string): ExpectedOrders {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-priority-e2e-"));
  const db = openDatabase({ dataDir: dir });
  try {
    seedPriorityFixtures(db, scoreDate, prevDate);
    const rising = getRisingForecast(db);
    return {
      knownExploited: getKnownExploited(db).map((row) => row.id),
      highestForecast: getHighestForecast(db).map((row) => row.id),
      newCritical: getNewCritical(db, new Date().toISOString()).map((row) => row.id),
      risingForecast: rising.map((row) => row.item.id),
      risingDeltas: rising.map((row) => row.deltaPp),
    };
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

async function renderedIds(page: Page, mode: string): Promise<string[]> {
  const rows = page.locator(`[data-testid="priority-list-${mode}"] [data-testid="priority-row"]`);
  return rows.evaluateAll((els) =>
    els.map((el) => el.getAttribute("data-cve-id")).filter((id): id is string => id !== null),
  );
}

test.describe.serial("priority list views", () => {
  const freshDate = day(0);
  const freshPrev = day(-7);
  let expected: ExpectedOrders;

  test.beforeAll(() => {
    mkdirSync(EVIDENCE_DIR, { recursive: true });
    expected = expectedFromServices(freshDate, freshPrev);
    const db = openDatabase({ dataDir: serverDataDir() });
    try {
      seedPriorityFixtures(db, freshDate, freshPrev);
    } finally {
      db.close();
    }
  });

  test.afterAll(() => {
    const db = openDatabase({ dataDir: serverDataDir() });
    try {
      wipeFixtures(db);
    } finally {
      db.close();
    }
  });

  test("service fixtures order the four views as the contract requires", () => {
    expect(expected.knownExploited).toEqual(["CVE-2099-1002", "CVE-2099-1001", "CVE-2099-1004"]);
    expect(expected.highestForecast).toEqual([
      "CVE-2099-1003",
      "CVE-2099-1008",
      "CVE-2099-1006",
      "CVE-2099-1002",
      "CVE-2099-1001",
      "CVE-2099-1005",
    ]);
    expect(expected.newCritical).toEqual(["CVE-2099-1002", "CVE-2099-1001"]);
    expect(expected.risingForecast).toEqual(["CVE-2099-1002", "CVE-2099-1001", "CVE-2099-1005"]);
    expect(expected.risingDeltas).toEqual(["8", "8", "1"]);
  });

  test("known-exploited renders service order with unknown EPSS labeled in place", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/priority?view=known-exploited");
    await expect(page.getByTestId("priority-root")).toBeVisible();
    await expect(page.getByTestId("priority-tab-known-exploited")).toHaveAttribute("aria-current", "page");
    await expect(page.locator('[data-testid^="priority-tab-"]')).toHaveCount(4);
    await expect(page.getByTestId("priority-ordering-known-exploited")).toContainText("dateAdded descending");
    await expect(page.getByTestId("priority-ordering-known-exploited")).toContainText("CVE ID ASCII ascending");
    await expect(renderedIds(page, "known-exploited")).resolves.toEqual(expected.knownExploited);
    const unknownRow = page.locator('[data-cve-id="CVE-2099-1004"]');
    await expect(unknownRow.getByTestId("priority-row-signals")).toContainText(
      "EPSS unavailable for this snapshot",
    );
    await expect(unknownRow.getByTestId("priority-row-signals")).toContainText("KEV listed");
    await expect(page.getByTestId("priority-coverage-known-exploited")).toContainText(
      "3 eligible of 7 published records",
    );
    await expect(page.getByTestId("priority-methodology-known-exploited").getByRole("link")).toHaveAttribute(
      "href",
      "/methodology",
    );
    await expect(page.getByTestId("priority-evidence-known-exploited")).toContainText("Current");
    await expect(page.getByTestId("priority-mode-nav").getByText("Popular")).toHaveCount(0);
    await expect(page.getByText("blended")).toHaveCount(0);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });

  test("highest-forecast renders raw-probability order with score date and model", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/priority?view=highest-forecast");
    await expect(page.getByTestId("priority-root")).toBeVisible();
    await expect(page.getByTestId("priority-ordering-highest-forecast")).toContainText(
      "raw EPSS probability descending",
    );
    await expect(renderedIds(page, "highest-forecast")).resolves.toEqual(expected.highestForecast);
    await expect(page.getByTestId("priority-ordering-highest-forecast")).toContainText(freshDate);
    await expect(page.getByTestId("priority-ordering-highest-forecast")).toContainText(MODEL);
    await expect(page.getByTestId("priority-coverage-highest-forecast")).toContainText(
      "6 eligible of 7 published records",
    );
    await expect(page.getByTestId("priority-evidence-highest-forecast")).toContainText("Current");
  });

  test("new-critical renders windowed order and names the ineligible cases", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/priority?view=new-critical");
    await expect(page.getByTestId("priority-root")).toBeVisible();
    await expect(page.getByTestId("priority-ordering-new-critical")).toContainText("[T - 30d, T)");
    await expect(page.getByTestId("priority-ordering-new-critical")).toContainText("ADP-only");
    await expect(renderedIds(page, "new-critical")).resolves.toEqual(expected.newCritical);
    await expect(page.getByTestId("priority-coverage-new-critical")).toContainText(
      "2 eligible of 7 published records",
    );
  });

  test("rising-forecast renders delta order with same-model movement labels", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/priority?view=rising-forecast");
    await expect(page.getByTestId("priority-root")).toBeVisible();
    await expect(page.getByTestId("priority-ordering-rising-forecast")).toContainText(
      "delta percentage-points descending",
    );
    await expect(page.getByTestId("priority-ordering-rising-forecast")).toContainText("never interpolated");
    await expect(renderedIds(page, "rising-forecast")).resolves.toEqual(expected.risingForecast);
    const first = page.locator('[data-cve-id="CVE-2099-1002"]');
    await expect(first.getByTestId("priority-row-signals")).toContainText("+8 percentage points");
    const last = page.locator('[data-cve-id="CVE-2099-1005"]');
    await expect(last.getByTestId("priority-row-signals")).toContainText("+1 percentage points");
    await expect(page.getByTestId("priority-coverage-rising-forecast")).toContainText(
      "3 eligible of 7 published records",
    );
  });

  for (const width of [360, 768, 1280]) {
    test(`priority renders without overflow at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/priority?view=known-exploited");
      await expect(page.getByTestId("priority-root")).toBeVisible();
      await expect(page.getByTestId("priority-list-known-exploited")).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);
      await page.screenshot({ path: `${EVIDENCE_DIR}/priority-known-exploited-${width}.png`, fullPage: true });
    });
  }

  test("priority captures every mode at desktop width", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    for (const mode of ["highest-forecast", "new-critical", "rising-forecast"] as const) {
      await page.goto(`/priority?view=${mode}`);
      await expect(page.getByTestId(`priority-list-${mode}`)).toBeVisible();
      await page.screenshot({ path: `${EVIDENCE_DIR}/priority-${mode}-1280.png`, fullPage: true });
    }
  });

  test("stale EPSS snapshot keeps dated values with a stale label", async ({ page }) => {
    const staleDate = day(-10);
    const stalePrev = day(-17);
    const db = openDatabase({ dataDir: serverDataDir() });
    try {
      seedPriorityFixtures(db, staleDate, stalePrev);
    } finally {
      db.close();
    }
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/priority?view=highest-forecast");
    await expect(page.getByTestId("priority-root")).toBeVisible();
    await expect(page.getByTestId("priority-evidence-highest-forecast")).toContainText("Stale");
    await expect(page.getByTestId("priority-evidence-highest-forecast-detail")).toContainText(
      "older than 2 UTC calendar days",
    );
    await expect(page.getByTestId("priority-evidence-highest-forecast-detail")).toContainText(staleDate);
    await expect(page.getByTestId("priority-list-highest-forecast")).toBeVisible();
    await page.goto("/priority?view=rising-forecast");
    await expect(page.getByTestId("priority-evidence-rising-forecast")).toContainText("Stale");
    await page.screenshot({ path: `${EVIDENCE_DIR}/priority-stale-1280.png`, fullPage: true });
    const restore = openDatabase({ dataDir: serverDataDir() });
    try {
      seedPriorityFixtures(restore, freshDate, freshPrev);
    } finally {
      restore.close();
    }
  });
});
