// P1.5: the 44px target rule is only auditable if the selector reaches the
// interactive chart marks. These tests prove the extended measurement on a real
// page: it flags a genuine undersized mark, ignores decoration, and reads a
// mark's hit target rather than the glyph painted inside it.
//
// The routes' own audits live in the per-page specs (`auditRoute`); this file is
// the proof that the audit can fail, so a future regression cannot pass by
// quietly shrinking a mark.

import { expect, test } from "@playwright/test";

import { MIN_TARGET, describeTarget, measureTargets, type TargetFailure } from "./a11y-audit";

/** The chart surface the fixtures are appended to: the tooltip host of the
 * Sankey and of the KEV rhythm, both on the overview page. */
const CHART_FRAME = ".chart-frame";

async function firstMark(page: import("@playwright/test").Page): Promise<void> {
  // The charts stream in after the shell, so a measurement taken at `load` can
  // find no marks at all and pass for the wrong reason.
  await expect(page.locator('[role="img"][tabindex], [role="button"]').first()).toBeVisible();
}

test("the audit fails on an undersized chart mark and never on decoration", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  await firstMark(page);
  const before = await measureTargets(page);

  await page.evaluate((frameSelector) => {
    const frame = document.querySelector(frameSelector);
    if (frame === null) throw new Error(`no ${frameSelector} to append to`);
    const add = (id: string, css: string, decorate: (el: HTMLElement) => void): void => {
      const el = document.createElement("div");
      el.dataset.testid = id;
      el.style.cssText = css;
      decorate(el);
      frame.append(el);
    };
    // A real mark: role-bearing and focusable, 30x30 — under the rule in both
    // dimensions, which is exactly what the audit has to catch.
    add("fixture-undersized-mark", "width:30px;height:30px", (el) => {
      el.setAttribute("role", "img");
      el.setAttribute("tabindex", "0");
      el.setAttribute("aria-label", "undersized fixture mark");
    });
    // Decoration that looks like a mark: a picture, never a target.
    add("fixture-decorative-mark", "width:8px;height:8px", (el) => {
      el.setAttribute("role", "img");
      el.setAttribute("aria-hidden", "true");
    });
    // A programmatic focus root: focusable through script, not pointed at.
    add("fixture-focus-root", "width:8px;height:8px", (el) => {
      el.setAttribute("tabindex", "-1");
    });
  }, CHART_FRAME);

  const after = await measureTargets(page);
  const added = (failures: readonly TargetFailure[]): string[] =>
    failures
      .filter((failure) => !before.some((known) => known.label === failure.label))
      .map(describeTarget);

  // The failure line this proves, printed so a run records it:
  //   mark div#fixture-undersized-mark "" 30x30
  const flagged = added(after);
  console.log(`[a11y] fixture proof: ${flagged.join("; ")}`);
  expect(flagged).toEqual(['mark div#fixture-undersized-mark "" 30x30']);

  // The two look-alikes are decoration: a picture and a script target. Neither
  // answers a pointer, so neither is a 44px target.
  expect(after.some((failure) => failure.id === "fixture-decorative-mark")).toBe(false);
  expect(after.some((failure) => failure.id === "fixture-focus-root")).toBe(false);
});

test("a mark is measured by its hit target, not by the bar painted inside it", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  await firstMark(page);

  // The shortest painted bar on the page: a zero month draws a 1px mark, which
  // would fail the rule on its own and is unhittable without its column.
  const column = await page.evaluate(() => {
    const bars = Array.from(document.querySelectorAll(".kev-bar"));
    const shortest = bars
      .map((bar) => ({
        id: bar.getAttribute("data-testid") ?? "",
        painted: bar.querySelector(".kev-bar-fill")?.getBoundingClientRect().height ?? 0,
        target: bar.getBoundingClientRect().height,
      }))
      .sort((a, b) => a.painted - b.painted)[0];
    return shortest ?? null;
  });
  expect(column, "the KEV rhythm renders at least one bar").not.toBeNull();
  if (column === null) return;
  expect(column.painted, "a zero month is a 1px painted mark").toBeLessThan(MIN_TARGET);
  expect(column.target, "the column behind it is the hit target").toBeGreaterThanOrEqual(
    MIN_TARGET,
  );

  // So the audit reports the column's height, never the painted bar's: the
  // violation that remains is the column's width, which is the real one.
  const reported = (await measureTargets(page)).find((failure) => failure.id === column.id);
  expect(reported?.height).toBe(Math.round(column.target));
});

test("the sparkline's full-plot hit band is the target, and it passes", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/priority?view=highest-forecast");
  await firstMark(page);

  const band = await page.evaluate(() => {
    const strip = document.querySelector('[data-testid="priority-row-epss-strip"]');
    if (strip === null) return null;
    const dot = strip.parentElement?.querySelector("circle");
    return {
      width: strip.getBoundingClientRect().width,
      height: strip.getBoundingClientRect().height,
      dot: dot?.getBoundingClientRect().width ?? 0,
    };
  });
  expect(band, "the sparkline renders").not.toBeNull();
  if (band === null) return;
  // One band over a dense series: the 5px observation dots are not the targets,
  // the 44px plot is, which is why no per-point target has to be 7px wide.
  expect(band.dot).toBeLessThan(MIN_TARGET);
  expect(band.height).toBeGreaterThanOrEqual(MIN_TARGET);
  expect(band.width).toBeGreaterThanOrEqual(MIN_TARGET);

  const undersized = (await measureTargets(page)).filter(
    (failure) => failure.id === "priority-row-epss-strip",
  );
  expect(undersized.map(describeTarget)).toEqual([]);
});
