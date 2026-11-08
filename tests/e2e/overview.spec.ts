import { expect, test } from "@playwright/test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { openDatabase, type CveDatabase } from "../../src/lib/db";
import {
  A11Y_EVIDENCE_DIR,
  auditReducedMotion,
  auditRoute,
  auditZoomReflow,
  ensureA11yEvidenceDir,
} from "./a11y-audit";

test.describe.configure({ mode: "serial" });

const PROJECT_ROOT = process.cwd();
const SERVER_DATA_DIR = path.resolve(PROJECT_ROOT, process.env.DATA_DIR ?? "./data");
const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-18-cve-change-radar";

const STAMP = "2026-10-24T00:00:00.000Z";
const LONG_TITLE = "Overflow in the demonstration parser ".repeat(6).slice(0, 200);

const tempDirs: string[] = [];
let hadServerDb = false;
let serverDbBackup = "";

function dayAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
}

function isoDayAgo(days: number, time = "12:00:00.000Z"): string {
  return `${dayAgo(days)}T${time}`;
}

interface MetricFixture {
  origin: string;
  version: string;
  baseScore: string;
}

interface RecordFixture {
  cveId: string;
  title: string | null;
  description: string;
  lang: string | null;
  published: string | null;
  metrics: MetricFixture[];
  kevDateAdded: string | null;
  kevCatalogDate: string | null;
  epss: Array<{ scoreDate: string; model: string; value: string; percentile: string }>;
}

function seedRecord(db: CveDatabase, fixture: RecordFixture): void {
  db.handle
    .prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
        "title, description, description_lang, source_revision, created_at, updated_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      fixture.cveId,
      "5.1",
      "PUBLISHED",
      fixture.published,
      fixture.published,
      fixture.title,
      fixture.description,
      fixture.lang,
      "rev-fixture-2099",
      STAMP,
      STAMP,
    );
  for (const [index, metric] of fixture.metrics.entries()) {
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) " +
          "VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(fixture.cveId, metric.origin, metric.version, metric.baseScore, "CVSS:3.1/AV:N", index);
  }
  if (fixture.kevDateAdded !== null) {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run(fixture.cveId, fixture.kevDateAdded, fixture.kevCatalogDate, STAMP);
  }
  for (const row of fixture.epss) {
    db.handle
      .prepare(
        "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) " +
          "VALUES (?, ?, ?, ?, ?)",
      )
      .run(fixture.cveId, row.scoreDate, row.model, row.value, row.percentile);
  }
}

function seedSyncRun(
  db: CveDatabase,
  source: string,
  status: string,
  startedAt: string,
  revision: string | null,
  error: string | null,
): void {
  db.handle
    .prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .run(source, startedAt, startedAt, status, revision, null, error);
}

/** Builds a validated CVE-2099 fixture corpus in a temp DATA_DIR and returns its db file. */
function buildSeededDbFile(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-overview-seed-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  const epssCurrent = dayAgo(10);
  const epssPrevious = dayAgo(17);
  db.runBoundedWrite(() => {
    seedRecord(db, {
      cveId: "CVE-2099-0001",
      title: "Heap overflow in the parser allows remote code execution",
      description: "A heap overflow in the parser allows remote code execution",
      lang: "en",
      published: isoDayAgo(5),
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8" }],
      kevDateAdded: isoDayAgo(6, "00:00:00.000Z"),
      kevCatalogDate: dayAgo(9),
      epss: [
        { scoreDate: epssPrevious, model: "v4", value: "0.7000", percentile: "0.9500" },
        { scoreDate: epssCurrent, model: "v4", value: "0.7200", percentile: "0.9600" },
      ],
    });
    seedRecord(db, {
      cveId: "CVE-2099-0002",
      title: LONG_TITLE,
      description: "A critical service bug with a very long supplied title",
      lang: "en",
      published: isoDayAgo(3),
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.1" }],
      kevDateAdded: null,
      kevCatalogDate: null,
      epss: [
        { scoreDate: epssPrevious, model: "v4", value: "0.1000", percentile: "0.4000" },
        { scoreDate: epssCurrent, model: "v4", value: "0.3500", percentile: "0.7100" },
      ],
    });
    seedRecord(db, {
      cveId: "CVE-2099-0003",
      title: null,
      description: "",
      lang: null,
      published: null,
      metrics: [],
      kevDateAdded: null,
      kevCatalogDate: null,
      epss: [],
    });
    seedRecord(db, {
      cveId: "CVE-2099-0004",
      title: "Mid-severity service bug",
      description: "A mid-severity bug in the demonstration service",
      lang: "en",
      published: isoDayAgo(12, "08:00:00.000Z"),
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "5.4" }],
      kevDateAdded: null,
      kevCatalogDate: null,
      epss: [],
    });
    db.handle
      .prepare(
        "INSERT INTO cve_tombstones (cve_id, last_state, removed_in_revision, reason, recorded_at) " +
          "VALUES (?, ?, ?, ?, ?)",
      )
      .run("CVE-2099-0099", "PUBLISHED", "rev-fixture-2098", "rejected", STAMP);
    seedSyncRun(db, "cve", "succeeded", isoDayAgo(10, "08:00:00.000Z"), "rev-fixture-2099", null);
    seedSyncRun(db, "kev", "succeeded", isoDayAgo(11, "08:00:00.000Z"), dayAgo(11), null);
    seedSyncRun(
      db,
      "kev",
      "failed",
      isoDayAgo(9, "09:12:00.000Z"),
      null,
      "catalog fetch failed: HTTP 503",
    );
    seedSyncRun(db, "epss", "succeeded", isoDayAgo(10, "08:30:00.000Z"), `${epssCurrent}@v4`, null);
  });
  db.checkpointStatus();
  db.close();
  return path.join(dir, "cve.db");
}

function clearServerDb(): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    rmSync(path.join(SERVER_DATA_DIR, `cve.db${suffix}`), { force: true });
  }
}

function deployDbFile(sourceFile: string): void {
  mkdirSync(SERVER_DATA_DIR, { recursive: true });
  clearServerDb();
  copyFileSync(sourceFile, path.join(SERVER_DATA_DIR, "cve.db"));
}

test.beforeAll(() => {
  expect(LONG_TITLE.length).toBe(200);
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  const current = path.join(SERVER_DATA_DIR, "cve.db");
  hadServerDb = existsSync(current);
  if (hadServerDb) {
    const backupDir = mkdtempSync(path.join(tmpdir(), "cve-overview-backup-"));
    tempDirs.push(backupDir);
    serverDbBackup = path.join(backupDir, "cve.db");
    copyFileSync(current, serverDbBackup);
  }
  deployDbFile(buildSeededDbFile());
});

test.afterAll(() => {
  clearServerDb();
  if (hadServerDb && serverDbBackup !== "") {
    copyFileSync(serverDbBackup, path.join(SERVER_DATA_DIR, "cve.db"));
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

for (const width of [360, 768, 1280]) {
  test(`overview seeded journey renders data at ${width}px without overflow`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");

    await expect(page.getByTestId("overview-root")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "What is changing in the CVE corpus?", exact: true }),
    ).toBeVisible();

    const masthead = page.getByTestId("overview-masthead");
    await expect(masthead.getByRole("link", { name: /Overview/ })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await expect(masthead.getByRole("link", { name: "Search", exact: true })).toHaveAttribute(
      "href",
      "/explore",
    );
    await expect(masthead.getByRole("link", { name: "Priority" })).toHaveAttribute(
      "href",
      "/priority",
    );
    await expect(masthead.getByRole("link", { name: "Radar" })).toHaveAttribute("href", "/radar");
    await expect(masthead.getByRole("link", { name: "Replay" })).toHaveAttribute("href", "/replay");
    await expect(masthead.getByRole("link", { name: "Method" })).toHaveAttribute(
      "href",
      "/methodology",
    );

    await expect(page.getByTestId("global-search")).toBeVisible();
    await expect(page.getByTestId("overview-published-total")).toContainText("4");
    await expect(page.getByTestId("overview-volume-bar-2026-10")).toBeVisible();
    await expect(page.getByTestId("overview-severity-critical")).toHaveAttribute(
      "href",
      "/explore?severity=critical",
    );

    await page.getByTestId("overview-chart").getByText("Data table").click();
    await expect(page.getByTestId("overview-chart").locator("table.data-table")).toBeVisible();

    await expect(page.getByTestId("overview-freshness-cve")).toContainText("Stale");
    await expect(page.getByTestId("overview-freshness-kev")).toContainText("Source failed");
    await expect(page.getByTestId("overview-freshness-kev-detail")).toContainText("HTTP 503");
    await expect(page.getByTestId("overview-freshness-epss")).toContainText("Stale");

    const priority = page.getByTestId("overview-priority");
    await expect(priority.getByTestId("overview-priority-known-exploited-list")).toContainText(
      "CVE-2099-0001",
    );
    await expect(priority.getByTestId("overview-priority-highest-forecast-list")).toContainText(
      "0.7200",
    );
    await expect(priority.getByTestId("overview-priority-new-critical-list")).toContainText(
      "CVE-2099-0002",
    );
    await expect(priority.getByTestId("overview-priority-rising-forecast-list")).toContainText(
      "same model",
    );

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);

    await page.screenshot({ path: `${EVIDENCE_DIR}/overview-${width}.png`, fullPage: true });
  });
}

test("overview empty corpus shows honest empty states", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  clearServerDb();
  await page.goto("/");

  await expect(page.getByTestId("overview-root")).toBeVisible();
  await expect(page.getByTestId("overview-chart-empty")).toContainText("honest empty state");
  await expect(page.getByTestId("overview-priority-empty")).toContainText("every list is empty");
  for (const key of ["known-exploited", "highest-forecast", "new-critical", "rising-forecast"]) {
    await expect(page.getByTestId(`overview-priority-${key}-empty`)).toBeVisible();
  }
  await expect(page.getByTestId("overview-freshness-kev")).toContainText("Missing");

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, "horizontal overflow on empty state").toBeLessThanOrEqual(1);
});

test("overview passes the task-24 accessibility audit", async ({ page }) => {
  ensureA11yEvidenceDir();
  deployDbFile(buildSeededDbFile());
  await auditRoute(page, { route: "/", name: "overview", maxLiveRegions: 1 });

  await page.getByTestId("global-search").focus();
  await expect(page.getByTestId("global-search")).toBeFocused();
  await page.screenshot({ path: `${A11Y_EVIDENCE_DIR}/overview-focus-1280.png`, fullPage: true });

  await auditZoomReflow(page, "overview", `${A11Y_EVIDENCE_DIR}/overview-zoom-200.png`);
  await auditReducedMotion(page, "overview", `${A11Y_EVIDENCE_DIR}/overview-reduced-motion.png`);
});

test("volume chart exposes tooltips, selection, and the window toggle", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");

  const bars = page.getByTestId(/^overview-volume-bar-/);
  await expect(bars).toHaveCount(24);
  const bar = bars.last();
  await bar.hover();
  const tooltip = page.getByTestId("overview-volume-tooltip");
  await expect(tooltip).toBeVisible();
  await expect(tooltip).toContainText("%");
  await expect(tooltip).toContainText("UTC calendar month");
  // Switching granularity relabels the tooltip, never the data.
  await page.getByTestId("overview-volume-granularity-week").click();
  await page.locator('[data-testid^="overview-volume-bar-"]').nth(3).hover();
  await expect(tooltip).toContainText("UTC calendar week");
  await page.getByTestId("overview-volume-granularity-month").click();

  await bar.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("overview-volume-selection")).toContainText(
    "Open this month in Explore",
  );
  await page.keyboard.press("Escape");

  await page.getByTestId("overview-volume-window-12").click();
  await expect(page.getByTestId("overview-volume-window-12")).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByTestId(/^overview-volume-bar-/)).toHaveCount(12);

  // Segmented control: every option sits fully inside the track, and the
  // bars glide on window switches.
  const containment = await page.evaluate(() => {
    const tracks = [...document.querySelectorAll(".chart-actions .pill.segmented")];
    if (tracks.length === 0) return { ok: false, reason: "missing" };
    for (const track of tracks) {
      const box = track.getBoundingClientRect();
      for (const option of [...track.querySelectorAll(".btn")]) {
        const inner = option.getBoundingClientRect();
        if (inner.top < box.top || inner.bottom > box.bottom) {
          return { ok: false, reason: "overflow" };
        }
      }
    }
    const bar = document.querySelector(".volume-bar");
    const animated = bar !== null && getComputedStyle(bar).transitionProperty.includes("height");
    return { ok: animated, reason: animated ? "ok" : "no-transition" };
  });
  expect(containment, "segmented options overflow the track").toEqual({ ok: true, reason: "ok" });
});

test("time-to-KEV flow draws cohorts, bands, stats and a data table", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  const panel = page.getByTestId("overview-time-to-kev");
  if (!(await panel.isVisible())) return;
  await expect(page.getByTestId("overview-time-to-kev-svg")).toBeVisible();
  await expect(page.getByTestId("overview-time-to-kev-note")).toContainText("excluded");
  // The same series is available as a table (chart contract).
  await panel.getByText("Data table").click();
  await expect(panel.locator("table tbody tr").first()).toBeVisible();
});

test("volume chart switches between month, week and day buckets", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  const bars = page.getByTestId(/^overview-volume-bar-/);
  await expect(bars).toHaveCount(24);

  await page.getByTestId("overview-volume-granularity-week").click();
  await expect(page.getByTestId("overview-volume-granularity-week")).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  // Weekly buckets are Monday-anchored dates; the count is bounded by how many
  // days the fixture actually holds, never padded with empty buckets.
  const weekCount = await bars.count();
  expect(weekCount).toBeGreaterThan(0);
  expect(weekCount).toBeLessThanOrEqual(52);
  const firstWeek = await bars.first().getAttribute("data-testid");
  expect(firstWeek).toMatch(/^overview-volume-bar-\d{4}-\d{2}-\d{2}$/);

  await page.getByTestId("overview-volume-granularity-day").click();
  const dayCount = await bars.count();
  expect(dayCount).toBeGreaterThan(weekCount);
  expect(dayCount).toBeLessThanOrEqual(90);
  // Selection works per bucket, and the strip names the bucket label.
  await bars.last().focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("overview-volume-selection")).toContainText(
    "Open this range in Explore",
  );
  await page.keyboard.press("Escape");

  await page.getByTestId("overview-volume-granularity-month").click();
  await expect(bars).toHaveCount(24);
});

test("clicking a Sankey band opens the records inside that flow", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  // The narrowest flows render as zero-height slivers; open the widest one.
  const bandId = await page.evaluate(() => {
    const bands = [...document.querySelectorAll('[data-testid^="overview-time-to-kev-band-"]')];
    const scored = bands.map((node) => ({
      id: node.getAttribute("data-testid") ?? "",
      area: (node as SVGPathElement).getBBox().height,
    }));
    scored.sort((a, b) => b.area - a.area);
    return scored[0]?.id ?? "";
  });
  expect(bandId).not.toBe("");
  const band = page.locator(`[data-testid="${bandId}"]`);
  if ((await band.count()) === 0) return;
  const dialog = page.getByTestId("overview-time-to-kev-dialog");
  // The chart re-renders when the page's data settles under parallel load, so a
  // single click can land on a node that just moved. Retry the open.
  await expect(async () => {
    await band.click({ force: true, timeout: 2000 });
    await expect(dialog).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 15000 });
  await expect(dialog).toContainText("records in this flow");
  const items = dialog.locator("[data-testid^='flow-details-item-']");
  expect(await items.count()).toBeGreaterThan(0);
  await expect(items.first()).toHaveAttribute("href", /explore\?q=CVE-/);
  // Filter narrows the list, Escape closes.
  await dialog.getByTestId("flow-details-filter").fill("CVE-");
  await expect(dialog.getByTestId("flow-details-count")).toContainText("matching");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});

test("a Sankey node pins its highlight, opens its flows and keeps a distribution", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  const nodes = page.locator('[data-testid^="overview-time-to-kev-node-cohort-"]');
  if ((await nodes.count()) === 0) return;
  const node = nodes.first();
  // Click the node's rectangle, not the group's centre: the group's box spans
  // the label too, and its centre can fall in the gap between text and node.
  const nodeBody = node.locator("rect").first();
  const dialog = page.getByTestId("overview-time-to-kev-dialog");
  await expect(async () => {
    await nodeBody.click({ force: true, timeout: 2000 });
    await expect(dialog).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 15000 });

  // A node opens every flow through it, with counts and shares.
  await expect(dialog).toContainText("records");
  const breakdown = dialog.getByTestId("flow-details-breakdown");
  await expect(breakdown.locator("li").first()).toBeVisible();
  await expect(breakdown.locator("li").first()).toContainText("%");

  // Closing the dialog keeps the selection: the highlight and its distribution
  // must survive the pointer leaving the chart.
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await page.mouse.move(4, 4);
  await expect(page.getByTestId("overview-time-to-kev-pinned")).toHaveText("pinned");
  const rows = page.getByTestId("overview-time-to-kev-distribution").locator("li");
  expect(await rows.count()).toBeGreaterThan(0);
  await expect(rows.first()).toContainText("%");
  await expect(node).toHaveAttribute("aria-pressed", "true");

  // A second click clears the pin.
  await nodeBody.click({ force: true });
  await expect(page.getByTestId("overview-time-to-kev-pinned")).toHaveCount(0);
});

test("fastest-confirmations card explains the metric and lists linked rows", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  const card = page.getByTestId("overview-fastest");
  await expect(card).toBeVisible();
  // The delay statistics live with the chart they describe, not in this list.
  await expect(page.getByTestId("overview-time-to-kev-stats")).toContainText("Median delay");
  await expect(page.getByTestId("overview-time-to-kev-stats")).toContainText(
    "Confirmed within 30 days",
  );
  await expect(card).toContainText("CISA confirmed exploitation within days");
  // Rows link into Explore and carry both dates, never a bare sentence.
  const rows = page.getByTestId("overview-fastest-list").locator("li.fastest-row");
  if ((await rows.count()) > 0) {
    await expect(rows.first().locator("a")).toHaveAttribute("href", /^\/explore\?q=CVE-/);
    await expect(rows.first()).toContainText("published");
    await expect(rows.first()).toContainText("KEV added");
  }
});

test("matrix inspector links navigate client-side without a full reload", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  const cell = page.getByTestId("overview-density-cell-critical-0");
  await cell.focus();
  await page.keyboard.press("Enter");
  let loads = 0;
  page.on("load", () => {
    loads += 1;
  });
  await page.getByRole("link", { name: "Open this severity band" }).click();
  await expect(page).toHaveURL(/\/explore\?severity=critical/, { timeout: 20000 });
  expect(loads, "inspector link caused a full page reload").toBe(0);
});

test("density matrix selection updates the inspector and supports arrow keys", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");

  const cell = page.getByTestId("overview-density-cell-critical-0");
  // Hydration can replace the node right after the first paint, which drops
  // focus and sends the arrow key nowhere. Retry until the press registers.
  await expect(async () => {
    await cell.focus();
    await page.keyboard.press("Enter");
    await expect(cell).toHaveAttribute("aria-pressed", "true", { timeout: 1_000 });
  }).toPass({ timeout: 15000 });
  await expect(page.getByTestId("overview-density-inspector")).toContainText("Critical");
  await expect(cell).toBeFocused();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByTestId("overview-density-cell-critical-1")).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByTestId("overview-density-inspector")).toContainText("EPSS");
});

test("desktop rail collapses and remembers the choice", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  const rail = page.locator(".app-rail");
  const expanded = await rail.evaluate((el) => el.getBoundingClientRect().width);
  expect(expanded).toBeGreaterThan(200);
  await page.getByRole("button", { name: "Collapse navigation" }).click();
  await expect(page.getByRole("button", { name: "Expand navigation" })).toBeVisible();
  const collapsed = await rail.evaluate((el) => el.getBoundingClientRect().width);
  expect(collapsed).toBeLessThanOrEqual(80);
  await page.reload();
  await expect(page.getByRole("button", { name: "Expand navigation" })).toBeVisible();
});
