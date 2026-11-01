import { expect, test } from "@playwright/test";
import path from "node:path";

import { openDatabase, type CveDatabase } from "../../src/lib/db";

// Relation graph journey: seeded KEV cohort with one shared CWE, rendered
// as labeled SVG nodes with an inspector and a focus mode. Self-seeded so
// no other suite's fixtures matter.
function serverDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") {
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
  }
  return path.join(process.cwd(), "data");
}

function seedGraph(db: CveDatabase): void {
  const nowIso = new Date().toISOString();
  db.runBoundedWrite(() => {
    const record = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const id of ["CVE-2099-1001", "CVE-2099-1002", "CVE-2099-1003"]) {
      record.run(
        id,
        "5.1",
        "PUBLISHED",
        "2026-10-20T00:00:00.000Z",
        `Supplied CNA title for ${id}.`,
        `Supplied description for ${id} with enough detail to render.`,
        "en",
        nowIso,
        nowIso,
      );
    }
    const kev = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, recorded_at) VALUES (?, ?, ?, ?, ?)",
    );
    kev.run("CVE-2099-1001", nowIso, nowIso, "GraphVendor", nowIso);
    kev.run("CVE-2099-1002", nowIso, nowIso, "GraphVendor", nowIso);
    kev.run("CVE-2099-1003", nowIso, nowIso, "OtherVendor", nowIso);
    const cwe = db.handle.prepare("INSERT OR IGNORE INTO kev_cwes (cve_id, cwe_id) VALUES (?, ?)");
    cwe.run("CVE-2099-1001", "CWE-78");
    cwe.run("CVE-2099-1002", "CWE-78");
  });
}

function wipeGraph(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    for (const id of ["CVE-2099-1001", "CVE-2099-1002", "CVE-2099-1003"]) {
      db.handle.prepare("DELETE FROM kev_cwes WHERE cve_id = ?").run(id);
      db.handle.prepare("DELETE FROM kev_entries WHERE cve_id = ?").run(id);
      db.handle.prepare("DELETE FROM cve_records WHERE cve_id = ?").run(id);
    }
  });
}

test.beforeAll(() => {
  const db = openDatabase({ dataDir: serverDataDir() });
  try {
    seedGraph(db);
  } finally {
    db.close();
  }
});

test.afterAll(() => {
  const db = openDatabase({ dataDir: serverDataDir() });
  try {
    wipeGraph(db);
  } finally {
    db.close();
  }
});

test("graph renders labeled nodes with an inspector", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  // Focused ego cohort: deterministic regardless of other suites' leftovers
  // in the shared dev database (the default top-EPSS cohort is covered by
  // unit tests on isolated temp DBs instead).
  await page.goto("/graph?focus=CVE-2099-1001");
  await expect(page.getByTestId("graph-root")).toBeVisible();
  await expect(page.getByTestId("graph-svg")).toBeVisible();
  await expect(page.getByTestId("graph-node-CVE-2099-1001")).toBeVisible();
  await expect(page.getByTestId("graph-coverage")).toContainText("centered on CVE-2099-1001");

  await page.getByTestId("graph-node-CVE-2099-1001").click();
  await expect(page.getByTestId("graph-inspector-id")).toContainText("CVE-2099-1001");
  await expect(page.getByTestId("graph-inspector-degree")).toContainText("1");
  await expect(page.getByTestId("graph-inspector")).toContainText("shared vendor label");
  await expect(page.getByTestId("graph-inspector")).toContainText("Open in Search");
});

test("graph focus centers an ego neighborhood", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph?focus=CVE-2099-1003");
  await expect(page.getByTestId("graph-coverage")).toContainText("centered on CVE-2099-1003");
  await expect(page.getByTestId("graph-node-CVE-2099-1003")).toBeVisible();
  await expect(page.getByTestId("graph-node-CVE-2099-1001")).toHaveCount(0);
});
