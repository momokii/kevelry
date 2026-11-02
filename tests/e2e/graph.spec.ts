import { expect, test } from "@playwright/test";

// Relation graph journey, deliberately fixture-free. The graph reads whatever
// KEV cohort the shared dev database holds; seeding rows here would leak into
// other suites (they assert exact priority orders, and pages cache for 60s).
// These tests therefore assert the contract on real data:
//   - landing ranks hubs and never pre-fills a center
//   - centering draws the ego graph, grouped attributes, and the reading guide
//   - "+N more" opens the complete attribute list in a dialog
//   - an unknown focus is refused with a message

/**
 * Most-connected hub on the landing page. Other suites leave their own KEV
 * fixtures in the shared database, so the first row is not guaranteed to have
 * links; scanning for the highest degree keeps these tests meaningful.
 */
async function topHub(
  page: import("@playwright/test").Page,
): Promise<{ id: string; degree: number } | null> {
  const hubs = page.getByTestId("graph-hubs");
  if (!(await hubs.isVisible())) return null;
  const rows = await hubs.locator("li").evaluateAll((items) =>
    items.map((item) => {
      const id = item.querySelector("a.graph-hub-id")?.textContent?.trim() ?? "";
      const badge = item.querySelector(".graph-hub-signals .badge")?.textContent ?? "";
      const degree = Number.parseInt(badge, 10);
      return { id, degree: Number.isFinite(degree) ? degree : 0 };
    }),
  );
  const best = rows
    .filter((row) => /^CVE-\d{4}-\d+$/.test(row.id))
    .sort((a, b) => b.degree - a.degree)[0];
  return best ?? null;
}

test("landing ranks hubs and never pre-fills a center", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph");
  await expect(page.getByTestId("graph-root")).toBeVisible();
  await expect(page.getByTestId("graph-landing")).toBeVisible();
  // No phantom default: the input is empty until the reader chooses.
  await expect(page.getByTestId("graph-focus-input")).toHaveValue("");
  // The reading guide is present and explains the contract.
  await expect(page.getByTestId("graph-guide")).toContainText("How to read this graph");

  const hub = await topHub(page);
  if (hub === null) {
    await expect(page.getByTestId("graph-empty")).toContainText("No KEV cohort");
    return;
  }
  const firstHub = page.getByTestId(`graph-hub-${hub.id}`);
  await expect(firstHub).toContainText("links");
});

test("centering draws the ego graph with grouped attributes and a way back", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph");
  const hub = await topHub(page);
  if (hub === null) {
    test.skip(true, "no KEV cohort in this database");
    return;
  }
  const id = hub.id;

  await page.goto(`/graph?focus=${encodeURIComponent(id)}`);
  await expect(page.getByTestId("graph-centered")).toBeVisible();
  await expect(page.getByTestId("graph-center-id")).toContainText(id);

  // A real drawing, a legend naming the three link kinds, and grouped lists.
  if (hub.degree > 0) {
    await expect(page.getByTestId("graph-svg")).toBeVisible();
    await expect(page.getByTestId("graph-legend")).toContainText("Shared CWE");
    await expect(page.getByTestId("graph-legend")).toContainText("Shared vendor");
    await expect(page.getByTestId("graph-legend")).toContainText("Shared reference host");
    await expect(page.getByTestId("graph-columns")).toBeVisible();
  } else {
    await expect(page.getByTestId("graph-no-links")).toContainText("No labeled links");
  }

  // The guide spells out what a line means and what it does not mean.
  const guide = page.getByTestId("graph-guide");
  await guide.locator("summary").click();
  await expect(guide).toContainText("What a dot is");
  await expect(guide).toContainText("What a line means");
  await expect(guide).toContainText("What a line does not mean");
  await expect(guide).toContainText(/advisory aggregators/i);

  // Back navigation to the overview.
  await expect(page.getByTestId("graph-back")).toContainText("Graph overview");
  await page.getByTestId("graph-back").click();
  await expect(page).toHaveURL(/\/graph(\?|$)/);
  await expect(page.getByTestId("graph-landing")).toBeVisible();
});

test("+N more opens the complete attribute list in a dialog", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph");
  const hub = await topHub(page);
  if (hub === null || hub.degree === 0) {
    test.skip(true, "no linked KEV cohort in this database");
    return;
  }
  await page.goto(`/graph?focus=${encodeURIComponent(hub.id)}`);

  const trigger = page.locator("[data-testid^='graph-more-']").first();
  if ((await trigger.count()) === 0) {
    test.skip(true, "this cohort has no attribute group above the drawing cap");
    return;
  }
  await trigger.click();

  const dialog = page.getByTestId("graph-more-dialog");
  await expect(dialog).toBeVisible();
  const items = dialog.locator("[data-testid^='graph-more-item-']");
  expect(await items.count()).toBeGreaterThan(2);
  // Every listed record links back into the graph.
  await expect(items.first()).toHaveAttribute("href", /focus=CVE-/);

  // Escape closes and returns focus to the page.
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});

test("an unknown focus is refused with a message, not a broken graph", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph?focus=CVE-1999-0001");
  await expect(page.getByTestId("graph-invalid")).toContainText(
    "not a KEV-listed PUBLISHED record",
  );
});
