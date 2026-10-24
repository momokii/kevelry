import { expect, test, type Page } from "@playwright/test";

const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-19-cve-change-radar";

const SEVERITY_BANDS = ["critical", "high", "medium", "low", "none", "legacy", "unknown"] as const;

async function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}

for (const width of [360, 768, 1280]) {
  test(`explore renders filters, ordering note, and honest states at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/explore");
    await expect(page.getByTestId("explore-root")).toBeVisible();
    await expect(page.getByTestId("explore-title")).toContainText("Explore CVE records");
    await expect(page.getByTestId("explore-filters")).toBeVisible();
    await expect(page.getByTestId("explore-query")).toBeVisible();
    await expect(page.getByTestId("explore-submit")).toBeVisible();

    for (const band of SEVERITY_BANDS) {
      await expect(
        page.getByTestId(`explore-severity-${band}`),
        `${band} chip at ${width}px`,
      ).toBeVisible();
    }
    await expect(page.getByTestId("explore-severity-critical")).not.toBeChecked();
    await expect(page.getByText("CVSS v4.0/v3.x from 9.0 to 10.0").first()).toBeVisible();
    await expect(page.getByText("CVSS v2.0 only, not compared with v3/v4").first()).toBeVisible();
    await expect(page.getByText("unscored under this view's policy").first()).toBeVisible();

    await expect(page.getByTestId("explore-kev-all")).toBeVisible();
    await expect(page.getByTestId("explore-kev-only")).toBeVisible();
    await expect(page.getByTestId("explore-kev-excluded")).toBeVisible();
    await expect(page.getByTestId("explore-epss-all")).toBeVisible();
    await expect(page.getByTestId("explore-epss-present")).toBeVisible();
    await expect(page.getByTestId("explore-epss-absent")).toBeVisible();
    await expect(page.getByTestId("explore-date-start")).toBeVisible();
    await expect(page.getByTestId("explore-date-end")).toBeVisible();
    await expect(page.getByTestId("explore-limit")).toBeVisible();
    await expect(page.getByTestId("explore-apply")).toBeVisible();
    await expect(page.getByTestId("explore-clear")).toBeVisible();

    await expect(page.getByTestId("explore-results")).toBeVisible();
    const listVisible = await page.getByTestId("explore-list").isVisible();
    if (listVisible) {
      await expect(page.getByTestId("explore-ordering")).toBeVisible();
      await expect(page.getByTestId("explore-coverage")).toContainText("Matching cohort:");
      await expect(page.getByTestId("explore-coverage-bands")).toContainText("By severity band:");
      const firstRow = page.getByTestId("explore-row").first();
      await expect(firstRow.getByTestId("explore-row-id")).toContainText(/CVE-/);
      await expect(firstRow.getByTestId("explore-row-excerpt")).not.toBeEmpty();
      await expect(firstRow.getByTestId("explore-row-signals")).not.toBeEmpty();
      await expect(firstRow.getByTestId("explore-row-dates")).not.toBeEmpty();
      const href = await firstRow.getByTestId("explore-row-action").getAttribute("href");
      expect(href, "official-record link").toMatch(/^https:\/\/www\.cve\.org\/CVERecord\?id=CVE-/);
      await expect(page.getByTestId("explore-page-count")).toContainText(
        /Showing \d+ to \d+ of \d+/,
      );
    } else {
      const emptyVisible = await page.getByTestId("explore-empty").isVisible();
      const unavailableVisible = await page.getByTestId("explore-unavailable").isVisible();
      expect(emptyVisible || unavailableVisible, "honest empty or unavailable state").toBe(true);
      if (emptyVisible) {
        await expect(page.getByTestId("explore-empty")).toContainText(
          /No (matches|published records)/,
        );
      } else {
        await expect(page.getByTestId("explore-unavailable")).toContainText("Snapshot unavailable");
      }
      await expect(page.getByTestId("explore-page-count")).toBeVisible();
    }

    await page.getByTestId("explore-query").focus();
    await expect(page.getByTestId("explore-query")).toBeFocused();
    const outline = await page
      .getByTestId("explore-query")
      .evaluate((el) => getComputedStyle(el).outlineWidth);
    expect(outline, "query input focus outline").not.toBe("0px");

    const over = await horizontalOverflow(page);
    expect(over, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);

    await page.screenshot({ path: `${EVIDENCE_DIR}/explore-${width}.png`, fullPage: true });
  });
}

test("explore filters are reachable and operable by keyboard alone", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/explore");
  await expect(page.getByTestId("explore-filters")).toBeVisible();

  await page.getByTestId("explore-query").focus();
  await page.keyboard.type("buffer overflow", { delay: 10 });
  await expect(page.getByTestId("explore-query")).toHaveValue("buffer overflow");

  const seen = new Set<string>();
  for (let step = 0; step < 40; step += 1) {
    const id = await page.evaluate(() => {
      const active = document.activeElement;
      return active instanceof HTMLElement ? (active.getAttribute("data-testid") ?? "") : "";
    });
    if (id !== "") seen.add(id);
    if (
      seen.has("explore-severity-critical") &&
      seen.has("explore-kev-all") &&
      seen.has("explore-apply")
    )
      break;
    await page.keyboard.press("Tab");
  }
  expect(seen.has("explore-severity-critical"), "severity chip tab-reachable").toBe(true);
  expect(seen.has("explore-kev-all"), "KEV group tab-reachable").toBe(true);
  expect(seen.has("explore-apply"), "apply action tab-reachable").toBe(true);

  await page.getByTestId("explore-severity-critical").focus();
  await expect(page.getByTestId("explore-severity-critical")).toBeFocused();
  await page.keyboard.press("Space");
  await expect(page.getByTestId("explore-severity-critical")).toBeChecked();
  await page.keyboard.press("Space");
  await expect(page.getByTestId("explore-severity-critical")).not.toBeChecked();

  // Native radio pattern: Tab lands on the checked member, arrows move within the group.
  await page.getByTestId("explore-kev-all").focus();
  await expect(page.getByTestId("explore-kev-all")).toBeFocused();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByTestId("explore-kev-only")).toBeFocused();
  await expect(page.getByTestId("explore-kev-only")).toBeChecked();
  const chipOutline = await page
    .getByTestId("explore-kev-only")
    .evaluate((el) => getComputedStyle(el).outlineWidth);
  expect(chipOutline, "filter focus outline").not.toBe("0px");

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-keyboard-1280.png`, fullPage: true });
});

test("explore names invalid filters and keeps typed text", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });

  await page.goto("/explore?dateStart=2026-10-22&dateEnd=2026-10-20");
  await expect(page.getByTestId("explore-invalid")).toContainText("earlier");
  await expect(page.getByTestId("explore-date-start")).toHaveValue("2026-10-22");
  await expect(page.getByTestId("explore-date-end")).toHaveValue("2026-10-20");

  await page.goto("/explore?severity=bogus");
  await expect(page.getByTestId("explore-invalid")).toContainText("Unknown severity band");

  await page.goto("/explore?limit=999");
  await expect(page.getByTestId("explore-invalid")).toContainText("integer");

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-invalid-1280.png`, fullPage: true });
});

test("explore renders hostile input inert without breaking layout", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 900 });
  const hostile = "<script>window.__xss=1</script><img src=x onerror=window.__xss=2>";
  await page.goto(`/explore?${new URLSearchParams({ q: hostile }).toString()}`);

  await expect(page.getByTestId("explore-title")).toContainText("Explore CVE records");
  await expect(page.getByTestId("explore-query")).toHaveValue(hostile);
  const executed = await page.evaluate(() => (window as unknown as { __xss?: number }).__xss);
  expect(executed, "hostile script must not execute").toBeUndefined();
  expect(await page.locator("script[src='x']").count(), "no injected elements").toBe(0);

  const over = await horizontalOverflow(page);
  expect(over, "horizontal overflow with hostile input at 360px").toBeLessThanOrEqual(1);

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-hostile-360.png`, fullPage: true });
});

test("explore survives long vendor-style labels and unbroken strings", async ({ page }) => {
  const longLabel = "Vendor label with a forty-character demonstration string";
  const unbroken = `https://www.cve.org/CVERecord?id=CVE-2026-1234${"a".repeat(120)}`;
  await page.setViewportSize({ width: 360, height: 900 });
  await page.goto(`/explore?${new URLSearchParams({ q: `${longLabel} ${unbroken}` }).toString()}`);

  await expect(page.getByTestId("explore-root")).toBeVisible();
  await expect(page.getByTestId("explore-query")).toHaveValue(`${longLabel} ${unbroken}`);
  const over360 = await horizontalOverflow(page);
  expect(over360, "horizontal overflow with long labels at 360px").toBeLessThanOrEqual(1);

  await page.setViewportSize({ width: 1280, height: 900 });
  const over1280 = await horizontalOverflow(page);
  expect(over1280, "horizontal overflow with long labels at 1280px").toBeLessThanOrEqual(1);

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-stress-360.png`, fullPage: true });
});
