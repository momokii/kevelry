// CWE taxonomy chips and the mitigation disclosure in the Priority KEV block
// (v3 E3 step 3b). Seeds the dev server's corpus under .e2e/ with a
// deterministic invented corpus plus a fixture MITRE catalog: a `known` entry
// with published mitigation text (carrying MITRE's `::…::` markers in storage,
// stripped on the read path), a `known` entry without mitigation, and an id
// absent from the catalog. Each test deploys the catalog state it asserts, and
// the baseline is restored afterwards so the next spec starts from the same
// rows. Serial: every test shares the one server corpus and swaps its catalog
// state.

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { expect, test, type Locator, type Page } from "@playwright/test";

import { openDatabase, type CveDatabase } from "../../src/lib/db";
import { deployE2eCorpus, resetToBaseline } from "./corpus";

test.describe.configure({ mode: "serial" });

const STAMP = "2026-10-24T00:00:00.000Z";
const MODEL = "v2026.06.15";
const CWE_VERSION = "1000-2";

const KNOWN_WITH_MITIGATION = "CVE-2099-7001";
const KNOWN_WITH_UNMAPPED = "CVE-2099-7002";
const KNOWN_SECOND = "CVE-2099-7003";

const LONG_NAME =
  "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')";
const CWE_79_NAME =
  "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')";
const MITIGATION_WITH_MARKERS =
  "::PHASE:Architecture and Design::Use a vetted library. ::PHASE:Implementation::Escape arguments before invoking the shell.";

const tempDirs: string[] = [];
let readyCatalogDb = "";
let emptyCatalogDb = "";

function dayAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
}

interface RecordFixture {
  cveId: string;
  title: string;
  kevDateAdded: string;
  kevDueDate: string;
  cwes: string[];
}

const FIXTURES: RecordFixture[] = [
  {
    cveId: KNOWN_WITH_MITIGATION,
    title: "Command injection in the demo service.",
    kevDateAdded: dayAgo(1),
    kevDueDate: dayAgo(-10),
    cwes: ["CWE-78", "CWE-79"],
  },
  {
    cveId: KNOWN_WITH_UNMAPPED,
    title: "Crafted input reaches an uncatalogued weakness class.",
    kevDateAdded: dayAgo(2),
    kevDueDate: dayAgo(-20),
    cwes: ["CWE-78", "CWE-999999"],
  },
  {
    cveId: KNOWN_SECOND,
    title: "Reflected input handling gap in the demo panel.",
    kevDateAdded: dayAgo(3),
    kevDueDate: dayAgo(-30),
    cwes: ["CWE-79"],
  },
];

function seedCorpus(db: CveDatabase, scoreDate: string): void {
  db.runBoundedWrite(() => {
    const record = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
        "title, description, description_lang, source_revision, created_at, updated_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    const kev = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, due_date, recorded_at) " +
        "VALUES (?, ?, ?, ?, ?)",
    );
    const kevCwe = db.handle.prepare("INSERT INTO kev_cwes (cve_id, cwe_id) VALUES (?, ?)");
    const epss = db.handle.prepare(
      "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) " +
        "VALUES (?, ?, ?, ?, ?)",
    );
    const cvss = db.handle.prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) " +
        "VALUES (?, ?, ?, ?, ?, ?)",
    );
    for (const fixture of FIXTURES) {
      record.run(
        fixture.cveId,
        "5.1",
        "PUBLISHED",
        `${dayAgo(4)}T00:00:00.000Z`,
        `${dayAgo(4)}T00:00:00.000Z`,
        fixture.title,
        `Supplied description for ${fixture.cveId}; the KEV block carries its CWE ids.`,
        "en",
        "rev-cwe-e2e",
        STAMP,
        STAMP,
      );
      kev.run(fixture.cveId, fixture.kevDateAdded, STAMP, fixture.kevDueDate, STAMP);
      for (const cwe of fixture.cwes) kevCwe.run(fixture.cveId, cwe);
      epss.run(fixture.cveId, scoreDate, MODEL, "0.20000", "0.80000");
      cvss.run(fixture.cveId, "CNA", "3.1", "9.8", "CVSS:3.1/AV:N", 0);
    }
    const sync = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    sync.run("cve", STAMP, STAMP, "succeeded", "cwe-e2e-cve", "hash-cve", null);
    sync.run("kev", STAMP, STAMP, "succeeded", "cwe-e2e-kev", "hash-kev", null);
    sync.run(
      "epss",
      STAMP,
      STAMP,
      "succeeded",
      `cwe-e2e-epss@${scoreDate}@${MODEL}`,
      "hash-epss",
      null,
    );
  });
}

function seedCatalog(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO cwe_catalog_meta (id, version, source, source_hash, retrieved_at, status, record_count, notes) " +
          "VALUES (1, ?, 'MITRE CWE', ?, ?, 'ready', 2, NULL)",
      )
      .run(CWE_VERSION, "a".repeat(64), STAMP);
    const insert = db.handle.prepare(
      "INSERT OR REPLACE INTO cwe_entries (cwe_id, name, abstraction, status, summary, mitigation, version, updated_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    // MITRE's control markers are stored verbatim and stripped on the read path,
    // so the disclosure below proves the stripping rather than the fixture.
    insert.run(
      "CWE-78",
      LONG_NAME,
      "Base",
      "Stable",
      "The product builds an OS command from externally-influenced input.",
      MITIGATION_WITH_MARKERS,
      CWE_VERSION,
      STAMP,
    );
    insert.run("CWE-79", CWE_79_NAME, "Base", "Stable", null, null, CWE_VERSION, STAMP);
  });
}

/** Build a temp-DATA_DIR database with the fixture corpus and (optionally) a ready catalog. */
function buildDbFile(withCatalog: boolean): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-priority-cwe-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  seedCorpus(db, dayAgo(0));
  if (withCatalog) seedCatalog(db);
  db.close();
  return path.join(dir, "cve.db");
}

/** Tab until the target is focused: proves real keyboard reachability and puts
 * the browser in keyboard modality so `:focus-visible` matches. */
async function tabTo(page: Page, target: Locator, maxPresses = 160): Promise<void> {
  for (let attempt = 0; attempt < maxPresses; attempt += 1) {
    await page.keyboard.press("Tab");
    if (await target.evaluate((el) => el === document.activeElement)) return;
  }
  throw new Error("target never received keyboard focus");
}

async function openRow(page: Page, id: string): Promise<Locator> {
  const row = page.locator(`[data-cve-id="${id}"]`);
  const toggle = row.getByRole("button").first();
  if ((await toggle.getAttribute("aria-expanded")) !== "true") await toggle.click();
  const block = row.getByTestId("priority-row-kev");
  await expect(block).toBeVisible();
  return block;
}

function parseRgb(value: string): [number, number, number] | null {
  const match = /rgba?\(([^)]+)\)/.exec(value);
  if (match === null) return null;
  const parts = (match[1] ?? "")
    .split(/[,\s/]+/)
    .filter((part) => part !== "")
    .map(Number);
  if (parts.length < 3 || parts.slice(0, 3).some((part) => !Number.isFinite(part))) return null;
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

function relativeLuminance([r, g, b]: [number, number, number]): number {
  const channel = (value: number): number => {
    const scaled = value / 255;
    return scaled <= 0.03928 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrastRatio(foreground: string, background: string): number {
  const fg = parseRgb(foreground);
  const bg = parseRgb(background);
  expect(fg, `parseable foreground colour (${foreground})`).not.toBeNull();
  expect(bg, `parseable background colour (${background})`).not.toBeNull();
  const a = relativeLuminance(fg as [number, number, number]);
  const b = relativeLuminance(bg as [number, number, number]);
  const [high, low] = a > b ? [a, b] : [b, a];
  return (high + 0.05) / (low + 0.05);
}

/** Computed chip colours with the effective (first opaque ancestor) background. */
async function chipColours(chip: Locator): Promise<{ color: string; background: string }> {
  return chip.evaluate((el) => {
    const idEl = el.querySelector('[data-testid="priority-row-kev-cwe-id"]') ?? el;
    const color = getComputedStyle(idEl).color;
    let node: Element | null = el;
    let background = "rgba(0, 0, 0, 0)";
    while (node !== null) {
      const candidate = getComputedStyle(node).backgroundColor;
      if (candidate !== "" && candidate !== "transparent" && candidate !== "rgba(0, 0, 0, 0)") {
        background = candidate;
        break;
      }
      node = node.parentElement;
    }
    return { color, background };
  });
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

test("known chip shows the id and the published name, linked to the MITRE page", async ({
  page,
}) => {
  deployE2eCorpus(readyCatalogDb);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/priority?view=known-exploited");
  await expect(page.getByTestId("priority-root")).toBeVisible();

  const block = await openRow(page, KNOWN_WITH_MITIGATION);
  const known = block.locator('[data-cwe-state="known"]').first();
  await expect(known.getByTestId("priority-row-kev-cwe-id")).toHaveText("CWE-78");
  await expect(known.getByTestId("priority-row-kev-cwe-name")).toHaveText(`· ${LONG_NAME}`);

  // The whole chip is the link, and it goes to the canonical MITRE definition.
  await expect(known).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/78.html");
  await expect(known).toHaveAttribute("target", "_blank");
  const rel = (await known.getAttribute("rel")) ?? "";
  expect(rel.split(" ").sort()).toEqual(["noopener", "noreferrer"]);

  // 44px target and a visible keyboard focus ring.
  const box = await known.boundingBox();
  expect(box, "chip has a box").not.toBeNull();
  expect((box as { height: number }).height).toBeGreaterThanOrEqual(44);
  await tabTo(page, known);
  const focus = await known.evaluate((el) => {
    const style = getComputedStyle(el);
    return { width: style.outlineWidth, style: style.outlineStyle, color: style.outlineColor };
  });
  expect(focus.style).not.toBe("none");
  expect(Number.parseFloat(focus.width)).toBeGreaterThanOrEqual(2);

  // No severity colouring anywhere in the chip row: a CWE id is not a band.
  const cweRow = block.getByTestId("priority-row-kev-cwes");
  await expect(cweRow.locator('[class*="badge"]')).toHaveCount(0);
  await expect(cweRow).not.toContainText(/critical|severity|vulnerable to/i);

  // The second id in the same row keeps its id and its own published name.
  await expect(block.getByTestId("priority-row-kev-cwe-id").nth(1)).toHaveText("CWE-79");
  await expect(block.getByTestId("priority-row-kev-cwe-name").nth(1)).toHaveText(
    `· ${CWE_79_NAME}`,
  );
});

test("an id absent from the loaded catalog still renders with its state words", async ({
  page,
}) => {
  deployE2eCorpus(readyCatalogDb);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/priority?view=known-exploited");
  await expect(page.getByTestId("priority-root")).toBeVisible();

  const block = await openRow(page, KNOWN_WITH_UNMAPPED);
  const unmapped = block.locator('[data-cwe-state="unmapped"]');
  await expect(unmapped).toHaveCount(1);
  await expect(unmapped.getByTestId("priority-row-kev-cwe-id")).toHaveText("CWE-999999");
  await expect(unmapped.getByTestId("priority-row-kev-cwe-state")).toHaveText(
    "not in the loaded catalog",
  );
  // Well-formed ids keep their canonical link even when the catalog cannot name them.
  await expect(unmapped).toHaveAttribute(
    "href",
    "https://cwe.mitre.org/data/definitions/999999.html",
  );
  // The mapped id in the same row still shows its name; nothing is dropped.
  await expect(block.getByTestId("priority-row-kev-cwe-id")).toHaveCount(2);
  await expect(block.locator('[data-cwe-state="known"]').first()).toContainText("CWE-78");
});

test("an empty catalog says taxonomy unavailable once and keeps every id", async ({ page }) => {
  deployE2eCorpus(emptyCatalogDb);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/priority?view=known-exploited");
  await expect(page.getByTestId("priority-root")).toBeVisible();

  const block = await openRow(page, KNOWN_WITH_MITIGATION);
  const cweRow = block.getByTestId("priority-row-kev-cwes");
  // One statement for the block, not one per chip.
  await expect(cweRow.getByTestId("priority-row-kev-cwe-taxonomy")).toHaveCount(1);
  await expect(cweRow.getByTestId("priority-row-kev-cwe-taxonomy")).toHaveText(
    "taxonomy unavailable",
  );
  const chips = cweRow.locator('[data-cwe-state="taxonomy-unavailable"]');
  await expect(chips).toHaveCount(2);
  await expect(chips.nth(0).getByTestId("priority-row-kev-cwe-id")).toHaveText("CWE-78");
  await expect(chips.nth(1).getByTestId("priority-row-kev-cwe-id")).toHaveText("CWE-79");
  // No invented names, no empty chips, and no mitigation block to disclose.
  await expect(cweRow.getByTestId("priority-row-kev-cwe-name")).toHaveCount(0);
  await expect(cweRow.getByTestId("priority-row-kev-cwe-mitigation")).toHaveCount(0);
  await expect(cweRow).not.toContainText("not in the loaded catalog");
});

test("mitigation disclosure opens by keyboard, names the catalog version, and has no markers", async ({
  page,
}) => {
  deployE2eCorpus(readyCatalogDb);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/priority?view=known-exploited");
  await expect(page.getByTestId("priority-root")).toBeVisible();

  const block = await openRow(page, KNOWN_WITH_MITIGATION);
  const disclosure = block.getByTestId("priority-row-kev-cwe-mitigation");
  await expect(disclosure).toHaveCount(1);
  const summary = disclosure.getByTestId("priority-row-kev-cwe-mitigation-summary");
  await expect(summary).toHaveText(`Mitigation (reference, MITRE CWE ${CWE_VERSION})`);
  await expect(disclosure).not.toHaveAttribute("open", "");

  // Keyboard: tabbing to the summary and pressing Enter opens it.
  await tabTo(page, summary);
  await page.keyboard.press("Enter");
  await expect(disclosure).toHaveAttribute("open", "");

  const text = disclosure.getByTestId("priority-row-kev-cwe-mitigation-text");
  await expect(text).toContainText("Use a vetted library.");
  await expect(text).toContainText("Escape arguments before invoking the shell.");
  // MITRE's `::…::` publishing markers are stripped on the read path.
  await expect(text).not.toContainText("::");
  const blockText = (await block.innerText()).replace(/\s+/g, " ");
  expect(blockText).not.toContain("::");
  expect(blockText).not.toContain("PHASE");
  // Context, not our remediation advice.
  await expect(disclosure).toContainText("applicability depends on the product");
  await expect(block.getByTestId("priority-row-kev-cwe-mitigation-help-trigger")).toHaveCount(1);
  await expect(block.getByTestId("priority-row-kev-cwe-mitigation-help-trigger")).toHaveAttribute(
    "aria-label",
    "About CWE mitigation",
  );

  // Copy rules: the block never claims exploitability or severity from a CWE.
  const pageText = (await page.locator("body").innerText()).toLowerCase();
  expect(pageText).not.toContain("vulnerable to");

  // CWE-79 published no mitigation, so it contributes no disclosure entry.
  await expect(disclosure).toContainText("CWE-78");
  await expect(disclosure).not.toContainText("CWE-79");
});

test("chips hold at 360px in dark theme with token-driven, readable colour", async ({ page }) => {
  deployE2eCorpus(readyCatalogDb);
  await page
    .context()
    .addCookies([{ name: "ui-theme", value: "dark", url: "http://localhost:3210" }]);
  await page.setViewportSize({ width: 360, height: 900 });
  await page.goto("/priority?view=known-exploited");
  await expect(page.getByTestId("priority-root")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  const block = await openRow(page, KNOWN_WITH_MITIGATION);
  const chip = block.locator('[data-cwe-state="known"]').first();
  await expect(chip.getByTestId("priority-row-kev-cwe-id")).toHaveText("CWE-78");

  const dark = await chipColours(chip);
  expect(
    contrastRatio(dark.color, dark.background),
    `dark chip contrast (${dark.color} on ${dark.background})`,
  ).toBeGreaterThanOrEqual(4.5);

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, "horizontal overflow from the CWE chips").toBeLessThanOrEqual(1);
  const blockOverflow = await block.evaluate((el) => el.scrollWidth - el.clientWidth);
  expect(blockOverflow, "KEV block scroll overflow").toBeLessThanOrEqual(1);

  // The tokens are the mechanism: flipping the theme changes the computed colour.
  await page.context().clearCookies();
  await page.goto("/priority?view=known-exploited");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  const lightBlock = await openRow(page, KNOWN_WITH_MITIGATION);
  const light = await chipColours(lightBlock.locator('[data-cwe-state="known"]').first());
  expect(light.color).not.toBe(dark.color);
  expect(
    contrastRatio(light.color, light.background),
    `light chip contrast (${light.color} on ${light.background})`,
  ).toBeGreaterThanOrEqual(4.5);
});
