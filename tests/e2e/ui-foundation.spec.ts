import { expect, test } from "@playwright/test";

const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-44-ui-foundation-cve-change-radar";

test("timezone switch changes rendered text and persists after reload", async ({ page }) => {
  await page.goto("/showcase");
  await page.evaluate(() => window.localStorage.clear());
  await page.reload();

  await expect(page.getByTestId("timetext-live")).toContainText("25 Oct 2026, 12:14 WIB");

  await page.getByTestId("timezone-select").selectOption("America/New_York");
  await expect(page.getByTestId("timetext-live")).toContainText("25 Oct 2026, 01:14 EDT");

  const stored = await page.evaluate(() => window.localStorage.getItem("ledger-timezone"));
  expect(stored).toBe("America/New_York");
  const cookies = await page.context().cookies();
  const cookieValue = cookies.find((entry) => entry.name === "ledger-timezone")?.value;
  expect(cookieValue ? decodeURIComponent(cookieValue) : cookieValue).toBe("America/New_York");

  await page.reload();
  await expect(page.getByTestId("timezone-select")).toHaveValue("America/New_York");
  await expect(page.getByTestId("timetext-live")).toContainText("25 Oct 2026, 01:14 EDT");

  // Restore the default for later tests and evidence screenshots.
  await page.getByTestId("timezone-select").selectOption("Asia/Jakarta");
  await expect(page.getByTestId("timetext-live")).toContainText("WIB");
});

test("helptip is keyboard operable and Escape closes it", async ({ page }) => {
  await page.goto("/showcase");

  const trigger = page.getByTestId("helptip-focus-trigger");
  const panel = page.getByTestId("helptip-focus-panel");

  await expect(trigger).toHaveAttribute("aria-expanded", "false");
  await expect(panel).toBeHidden();

  // The pinned demo renders open until the visitor clicks elsewhere.
  await expect(page.getByTestId("helptip-open-panel")).toBeVisible();

  await trigger.focus();
  await expect(panel).toBeVisible();
  await expect(trigger).toHaveAttribute("aria-expanded", "true");

  await trigger.press("Escape");
  await expect(panel).toBeHidden();
  await expect(trigger).toBeFocused();

  await trigger.click();
  await expect(panel).toBeVisible();
  await page.mouse.click(10, 10);
  await expect(panel).toBeHidden();

  await expect(page.getByTestId("timetext-invalid-missing")).toContainText("not recorded");
  await expect(page.getByTestId("timetext-missing-missing")).toContainText("not recorded");
});

for (const width of [360, 768, 1280]) {
  test(`ui foundation sections render without overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/showcase");

    for (const id of [
      "state-time-live",
      "state-time-jakarta",
      "state-time-utc",
      "state-time-newyork",
      "state-time-relative",
      "state-time-dateonly",
      "state-time-invalid",
      "state-time-missing",
      "state-helptip-closed",
      "state-helptip-open",
      "state-helptip-focus",
      "state-emphasis-value",
      "state-emphasis-caveat",
      "state-emphasis-label",
    ]) {
      await expect(page.getByTestId(id).first(), `${id} at ${width}px`).toBeVisible();
    }

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);

    await page.getByTestId("state-time-live").scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${EVIDENCE_DIR}/showcase-foundation-${width}.png` });
  });
}
