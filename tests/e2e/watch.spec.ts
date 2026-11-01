import { expect, test } from "@playwright/test";
import path from "node:path";

import { openDatabase, type CveDatabase } from "../../src/lib/db";

// Watch journey: star toggles persist browser-privately, and /watch hydrates
// stored IDs through the read-only API. No account, no server record.
// Self-seeded: priority.spec wipes its own fixtures in afterAll, so this
// file owns its records.
function serverDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") {
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
  }
  return path.join(process.cwd(), "data");
}

function seedWatchRecord(db: CveDatabase): void {
  const nowIso = new Date().toISOString();
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        "CVE-2099-1001",
        "5.1",
        "PUBLISHED",
        "2026-10-20T00:00:00.000Z",
        "Supplied CNA title: watched demo flaw.",
        "Supplied description for CVE-2099-1001 with enough detail to render an excerpt.",
        "en",
        nowIso,
        nowIso,
      );
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run("CVE-2099-1001", nowIso, nowIso, nowIso);
  });
}

function wipeWatchRecord(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    db.handle.prepare("DELETE FROM kev_entries WHERE cve_id = ?").run("CVE-2099-1001");
    db.handle.prepare("DELETE FROM cve_records WHERE cve_id = ?").run("CVE-2099-1001");
  });
}

test.beforeAll(() => {
  const db = openDatabase({ dataDir: serverDataDir() });
  try {
    // Idempotent: other suites share these fixture IDs and may leave rows
    // behind when a run aborts before their afterAll wipe.
    wipeWatchRecord(db);
    seedWatchRecord(db);
  } finally {
    db.close();
  }
});

test.afterAll(() => {
  const db = openDatabase({ dataDir: serverDataDir() });
  try {
    wipeWatchRecord(db);
  } finally {
    db.close();
  }
});

test("star persists across reload and /watch lists it", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/priority?view=known-exploited");
  await expect(page.getByTestId("priority-root")).toBeVisible();

  const star = page.getByTestId("priority-watch-CVE-2099-1001");
  await expect(star).toBeVisible();
  await expect(star).toHaveAttribute("aria-pressed", "false");
  await star.click();
  await expect(star).toHaveAttribute("aria-pressed", "true");

  await page.reload();
  await expect(page.getByTestId("priority-watch-CVE-2099-1001")).toHaveAttribute(
    "aria-pressed",
    "true",
  );

  await page.goto("/watch");
  await expect(page.getByTestId("watch-root")).toBeVisible();
  await expect(page.getByTestId("watch-list")).toBeVisible();
  await expect(page.getByTestId("watch-row-CVE-2099-1001-id")).toContainText("CVE-2099-1001");
  await expect(page.getByTestId("watch-row-CVE-2099-1001-signals")).not.toBeEmpty();

  await page.getByTestId("watch-remove-CVE-2099-1001").click();
  await expect(page.getByTestId("watch-empty")).toBeVisible();
  await page.goto("/priority?view=known-exploited");
  await expect(page.getByTestId("priority-watch-CVE-2099-1001")).toHaveAttribute(
    "aria-pressed",
    "false",
  );
});

test("watch rail link navigates and empty state explains privacy", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  await page.getByRole("link", { name: "Watch" }).first().click();
  await expect(page).toHaveURL("/watch");
  await expect(page.getByTestId("watch-empty")).toContainText("No watched CVEs yet");
  await expect(page.getByTestId("watch-empty")).toContainText("No account");
});
