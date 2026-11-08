import { expect, test, type Page } from "@playwright/test";

// Watch journey: the list is browser-private (localStorage) and every row is
// hydrated through the read-only API.
//
// The API is stubbed here on purpose. `explore.spec` replaces the server's
// database file for its own fixture, so a dev-server read handle can keep
// pointing at the replaced inode for the rest of a suite run; a test that seeds
// the real database is therefore order-dependent. Stubbing keeps this file about
// the one thing it owns — the row mapping and the persistence contract — while
// the real endpoint stays covered by the API suite and by Search's own specs.

const WATCH_ID = "CVE-2099-7001";

async function stubRecord(page: Page, overrides: Record<string, unknown> = {}): Promise<void> {
  const body = {
    data: {
      cveId: WATCH_ID,
      title: "Stubbed record with one tagged reference",
      excerpt: "Stubbed excerpt for the watch row.",
      publishedAt: "2026-10-20T00:00:00.000Z",
      officialUrl: `https://www.cve.org/CVERecord?id=${WATCH_ID}`,
      kev: { listed: true, dateAdded: "2026-10-21" },
      epss: { status: "known", value: 0.00412, percentile: 0.5, scoreDate: "2026-11-08" },
      cvssPrimary: { status: "known", baseScore: 9.8, version: "3.1" },
      exploitReferenceStatus: "tagged",
      exploitReferences: [{ url: "https://example.test/poc-7001" }],
      ...overrides,
    },
  };
  await page.route(`**/api/v1/cves/${WATCH_ID}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) }),
  );
}

async function watched(page: Page, ids: readonly string[]): Promise<void> {
  await page.addInitScript((list) => {
    window.localStorage.setItem("ui-watch", JSON.stringify(list));
  }, ids);
}

test("a watched record with a tagged reference links its evidence", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await stubRecord(page);
  await watched(page, [WATCH_ID]);
  await page.goto("/watch");

  // The badge is the link itself: Watch never claims a tag without evidence.
  const badge = page.getByTestId(`watch-row-${WATCH_ID}-exploit`);
  await expect(badge).toBeVisible({ timeout: 20_000 });
  await expect(badge).toHaveAttribute("href", "https://example.test/poc-7001");
  await expect(badge).toHaveAttribute("rel", "noreferrer noopener");
  await expect(badge).toContainText("exploit ref");
  await expect(page.getByTestId(`watch-row-${WATCH_ID}-signals`)).toContainText(
    "tagged exploit reference",
  );
});

test("watch rows show the same signals as the rest of the console", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await stubRecord(page, { exploitReferenceStatus: "none", exploitReferences: [] });
  await watched(page, [WATCH_ID]);
  await page.goto("/watch");

  const row = page.getByTestId(`watch-row-${WATCH_ID}`);
  await expect(row).toBeVisible({ timeout: 20_000 });
  await expect(row).toContainText("KEV");
  await expect(row).toContainText("0.41%");
  await expect(row).toContainText("9.8");
  // No tag: no badge, and the summary says so instead of staying silent.
  await expect(page.getByTestId(`watch-row-${WATCH_ID}-exploit`)).toHaveCount(0);
  await expect(page.getByTestId(`watch-row-${WATCH_ID}-signals`)).toContainText(
    "No tagged exploit reference",
  );
});

test("unwatching clears the stored list and survives a reload", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await stubRecord(page);
  await watched(page, [WATCH_ID]);
  await page.goto("/watch");
  await expect(page.getByTestId(`watch-row-${WATCH_ID}-id`)).toContainText(WATCH_ID, {
    timeout: 20_000,
  });

  await page.getByTestId(`watch-remove-${WATCH_ID}`).click();
  await expect(page.getByTestId("watch-empty")).toBeVisible();

  // The stored list must be empty, not just the rendered one. (Reloading here
  // would re-run the init script that seeds the id, so persistence is checked in
  // a second tab of the same context, which shares localStorage.)
  await expect
    .poll(async () => page.evaluate(() => window.localStorage.getItem("ui-watch")))
    .toEqual("[]");

  const second = await page.context().newPage();
  try {
    await second.goto("/watch");
    await expect(second.getByTestId("watch-empty")).toBeVisible();
  } finally {
    await second.close();
  }
});

test("a record missing from the snapshot stays watched with an honest note", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.route(`**/api/v1/cves/${WATCH_ID}`, (route) =>
    route.fulfill({ status: 404, contentType: "application/json", body: "{}" }),
  );
  await watched(page, [WATCH_ID]);
  await page.goto("/watch");

  await expect(page.getByTestId(`watch-row-${WATCH_ID}`)).toContainText("No longer PUBLISHED", {
    timeout: 20_000,
  });
  // It is still listed: the reader chose to keep it.
  await expect(page.getByTestId(`watch-row-${WATCH_ID}`)).toBeVisible();
});

test("watch rail link navigates and empty state explains privacy", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  await page
    .getByRole("navigation", { name: "Primary" })
    .getByRole("link", { name: "Watch" })
    .click();
  await expect(page).toHaveURL(/\/watch$/);
  await expect(page.getByTestId("watch-root")).toBeVisible();
  await expect(page.getByTestId("watch-empty")).toContainText("browser");
});
