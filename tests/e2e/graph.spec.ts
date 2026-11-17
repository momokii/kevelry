import { expect, test } from "@playwright/test";

import {
  BASELINE_COHORT_SIZE,
  DENSE_COHORT_SIZE,
  buildBaselineDbFile,
  deployE2eCorpus,
  resetToBaseline,
} from "./corpus";

// Relation graph journey, deliberately fixture-free: it seeds nothing itself.
// It asserts the contract on the suite's standard corpus (tests/e2e/corpus.ts),
// deployed here so the branches below depend on that data alone — before the
// corpus moved under .e2e/, whatever the previous spec left in data/cve.db
// decided whether the skip guards fired, and the skip count moved between a
// standalone run and a full-suite run.
//   - landing ranks hubs and never pre-fills a center
//   - centering draws the ego graph, grouped attributes, and the reading guide
//   - "+N more" opens the complete attribute list in a dialog
//   - an unknown focus is refused with a message

// The server must be reading the suite's own corpus, never the checkout's
// data/cve.db (which a deployed instance may hold open). The marker revision is
// seeded only by the baseline builder, so this fails loudly instead of quietly
// asserting against someone else's data.
test.beforeAll(async ({ request }) => {
  resetToBaseline();
  const response = await request.get("/api/v1/overview");
  expect(response.ok()).toBe(true);
  const body = (await response.json()) as {
    coverage: { eligibleCohort: number };
    provenance: { sources: { cve: { revision: string | null } } };
  };
  expect(
    body.provenance.sources.cve.revision,
    "the dev server must read DATA_DIR=.e2e/data, not data/cve.db",
  ).toBe("rev-e2e-baseline");
  expect(body.coverage.eligibleCohort).toBe(BASELINE_COHORT_SIZE);
});

/**
 * Most-connected hub on the landing page. The baseline corpus gives every KEV
 * record the same vendor and CWE, so degrees tie; the scan still sorts instead
 * of trusting row order, and a corpus with no cohort yields null.
 */
async function topHub(
  page: import("@playwright/test").Page,
): Promise<{ id: string; degree: number } | null> {
  const hubs = page.getByTestId("graph-hubs");
  // Wait for the landing to settle on one of its two honest outcomes. Unlike
  // an assertion, isVisible() does not wait, so without this a streamed page
  // can still be mid-render when the check runs.
  await expect(
    page.locator('[data-testid="graph-hubs"], [data-testid="graph-empty"]').first(),
  ).toBeVisible();
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

  // The dialog wrapper and its children share the `graph-more-` testid prefix,
  // so the trigger is selected by its button role — otherwise the locator can
  // resolve to the always-present closed dialog and the click never completes.
  const trigger = page.locator("[data-testid^='graph-more-'][role='button']").first();
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
  // Rows carry real context, not bare identifiers.
  const firstRow = dialog.locator(".graph-dialog-row").first();
  await expect(firstRow.locator(".graph-dialog-title")).not.toBeEmpty();
  await expect(firstRow.locator(".graph-dialog-meta")).toContainText(/Published|unknown/);
  await expect(firstRow.locator(".graph-dialog-badges")).toContainText(
    /EPSS|unscored|critical|high|medium|low|legacy/,
  );
  // The dialog is a member list, not a record detail: severity is a badge per
  // row and the secondary CVSS block never appears here.
  await expect(dialog.getByTestId("priority-row-cvss-secondary")).toHaveCount(0);
  await expect(dialog.getByText("context only")).toHaveCount(0);

  // A long group gets real affordances, not an endless scroll.
  await expect(dialog.getByTestId("graph-more-count")).toContainText("group holds");
  await expect(dialog.getByTestId("graph-more-list").locator("li")).toHaveCount(10);
  await dialog.getByTestId("graph-more-next").click();
  await expect(dialog.getByTestId("graph-more-page")).toContainText("Page 2 of");
  await dialog.getByTestId("graph-more-prev").click();
  await expect(dialog.getByTestId("graph-more-page")).toContainText("Page 1 of");

  // Filtering narrows the set and resets to page 1.
  const firstId =
    (await dialog.locator("[data-testid^='graph-more-item-']").first().textContent())?.trim() ?? "";
  await dialog.getByTestId("graph-more-filter").fill(firstId);
  await expect(dialog.getByTestId("graph-more-list").locator("li")).toHaveCount(1);

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

// Escape-after-filtering is the regression this file exists to catch: a
// `type="search"` input swallows the first Escape to clear its own text, so the
// dialog never receives `cancel` and stays open. The cohort below is deployed
// here rather than borrowed, so the trigger always exists once the fixture is
// seeded: with `DENSE_COHORT_SIZE` records sharing one vendor and one CWE, every
// attribute group is above the five-per-attribute drawing cap.
test.describe("graph attribute dialog", () => {
  test.beforeAll(() => {
    deployE2eCorpus(buildBaselineDbFile(DENSE_COHORT_SIZE));
  });

  test.afterAll(() => {
    resetToBaseline();
  });

  test("Escape closes the attribute dialog after the filter has been used", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/graph?focus=CVE-2099-0001");
    await expect(page.getByTestId("graph-centered")).toBeVisible();

    const trigger = page.locator("[data-testid^='graph-more-'][role='button']").first();
    await expect(trigger).toBeVisible();
    await trigger.click();

    const dialog = page.getByTestId("graph-more-dialog");
    await expect(dialog).toBeVisible();

    // Typing into the filter is what arms the swallowed-Escape path.
    const filter = dialog.getByTestId("graph-more-filter");
    await filter.fill("CVE-2099");
    await expect(filter).toHaveValue("CVE-2099");

    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();

    // Closing on Escape must also drop the filter, so the next open is clean.
    await trigger.click();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId("graph-more-filter")).toHaveValue("");
    await expect(dialog.getByTestId("graph-more-list").locator("li").first()).toBeVisible();
  });
});
