import { expect, test } from "@playwright/test";

const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-21-cve-change-radar";

for (const width of [360, 768, 1280]) {
  test(`radar feed and before/after inspector at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/radar");
    await expect(page.getByTestId("radar-root")).toBeVisible();
    // Wait for client hydration before any interaction; pre-hydration
    // clicks on server-rendered markup would be silent no-ops.
    await expect(page.getByTestId("radar-root")).toHaveAttribute("data-hydrated", "true", {
      timeout: 60000,
    });

    // Change day is the default pair: nine retained-snapshot events covering
    // KEV added, KEV removed, CNA changed, forecast changed, corrected,
    // rejected, list entered, list exited, and a rank-only move.
    const feed = page.getByTestId("radar-feed");
    await expect(feed).toBeVisible();
    await expect(feed.locator("[data-testid^='radar-event-']")).toHaveCount(9);

    // Every change kind carries a text-plus-symbol label, never color alone.
    await expect(page.getByTestId("radar-feed")).toContainText("[+] KEV added");
    await expect(page.getByTestId("radar-feed")).toContainText("[-] KEV removed");
    await expect(page.getByTestId("radar-feed")).toContainText("[~] CNA changed");
    await expect(page.getByTestId("radar-feed")).toContainText("[~] Forecast changed");
    await expect(page.getByTestId("radar-feed")).toContainText(
      "[R] Rank-only move (no source change)",
    );

    // Inspector opens on the first event with labeled Before/After field rows
    // plus source revisions and observation times.
    const inspector = page.getByTestId("radar-inspector");
    await expect(inspector).toBeVisible();
    await expect(inspector).toContainText("Before: 2026-10-23 snapshot");
    await expect(inspector).toContainText("After: 2026-10-24 snapshot");
    await expect(page.getByTestId("radar-inspector-evidence-detail")).toContainText("rev-a431");
    await expect(page.getByTestId("radar-inspector-evidence-detail")).toContainText(
      "observed 2026-10-24T08:00:00.000Z",
    );

    // Rank-only movement is labeled as such and never as a source change.
    await page.getByTestId("radar-event-CVE-2099-0006-rank-moved").click();
    await expect(page.getByTestId("radar-inspector-title")).toContainText("Rank-only move");
    await expect(page.getByTestId("radar-inspector-rank-note")).toContainText(
      "Rank-only move: source signals are unchanged",
    );

    // Kind filter narrows the feed; clearing restores it.
    await page.getByTestId("radar-filter-forecast-changed").click();
    await expect(feed.locator("[data-testid^='radar-event-']")).toHaveCount(1);
    await expect(page.getByTestId("radar-event-CVE-2099-0003-forecast-changed")).toBeVisible();
    await page.getByTestId("radar-filter-all").click();
    await expect(feed.locator("[data-testid^='radar-event-']")).toHaveCount(9);

    // No causal claims about EPSS internals, no first-exploit inference.
    await expect(page.getByTestId("radar-root")).not.toContainText("first exploit");
    await expect(page.getByTestId("radar-root")).not.toContainText("first-exploit");

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);

    await page.screenshot({ path: `${EVIDENCE_DIR}/radar-${width}.png`, fullPage: true });

    // Quiet day: identical retained snapshots render an honest quiet state,
    // not fabricated activity.
    await page.getByTestId("radar-day-select").selectOption({ index: 1 });
    await expect(page.getByTestId("radar-quiet")).toBeVisible();
    await expect(page.getByTestId("radar-quiet-copy")).toContainText(
      "Quiet day: no source changes observed",
    );
    await expect(page.getByTestId("radar-feed")).toHaveCount(0);
    await page.screenshot({ path: `${EVIDENCE_DIR}/radar-quiet-${width}.png`, fullPage: true });
  });
}
