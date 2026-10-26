import { mkdirSync } from "node:fs";
import { expect, type Page } from "@playwright/test";

export const A11Y_EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-24-cve-change-radar";

export function ensureA11yEvidenceDir(): void {
  mkdirSync(A11Y_EVIDENCE_DIR, { recursive: true });
}

export interface AuditOptions {
  route: string;
  name: string;
  maxLiveRegions: number;
}

interface ControlFailure {
  kind: string;
  label: string;
  width: number;
  height: number;
}

function controlLabel(el: Element): string {
  const testId = el.getAttribute("data-testid") ?? "";
  const text = (el.textContent ?? "").trim().slice(0, 48);
  return `${el.tagName.toLowerCase()}${testId === "" ? "" : `#${testId}`} "${text}"`;
}

export async function auditNoHorizontalOverflow(page: Page, context: string): Promise<void> {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, `horizontal overflow (${context})`).toBeLessThanOrEqual(1);
}

export async function auditRoute(page: Page, options: AuditOptions): Promise<void> {
  const { route, name, maxLiveRegions } = options;
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(route);

  const root = page.locator("#main-content");
  await expect(root, `${name}: skip-link target #main-content exists`).toHaveCount(1);
  await expect(page.locator(".ledger-skip-link"), `${name}: skip link present`).toHaveAttribute(
    "href",
    "#main-content",
  );

  const h1Count = await page.locator("h1").count();
  expect(h1Count, `${name}: exactly one h1`).toBe(1);
  const levels = await page.evaluate(() =>
    Array.from(document.querySelectorAll("h1, h2, h3, h4")).map((el) =>
      Number(el.tagName.slice(1)),
    ),
  );
  expect(levels[0], `${name}: first heading is h1`).toBe(1);
  for (let index = 1; index < levels.length; index += 1) {
    const previous = levels[index - 1] as number;
    const current = levels[index] as number;
    expect(
      current - previous,
      `${name}: heading level never skips (position ${index})`,
    ).toBeLessThanOrEqual(1);
  }

  const badImages = await page.evaluate(
    () =>
      Array.from(document.querySelectorAll("img")).filter(
        (img) =>
          img.getAttribute("aria-hidden") !== "true" &&
          (img.getAttribute("alt") ?? "").trim() === "",
      ).length,
  );
  expect(badImages, `${name}: every image has alt text`).toBe(0);

  const unlabeledControls = await page.evaluate(
    () =>
      Array.from(document.querySelectorAll("input, select, textarea")).filter((el) => {
        const input = el as HTMLInputElement;
        if (input.type === "hidden") return false;
        const aria = (el.getAttribute("aria-label") ?? "").trim();
        if (aria !== "") return false;
        const labelledBy = el.getAttribute("aria-labelledby") ?? "";
        if (labelledBy.trim() !== "") return false;
        const id = el.getAttribute("id") ?? "";
        if (id !== "" && document.querySelector(`label[for="${id}"]`) !== null) return false;
        if (el.closest("label") !== null) return false;
        if (el.closest("fieldset") !== null && el.tagName === "INPUT") {
          const group = el.closest("fieldset")?.querySelector("legend");
          if (group !== null) return false;
        }
        return true;
      }).length,
  );
  expect(unlabeledControls, `${name}: every form control has an accessible name`).toBe(0);

  const unnamedActions = await page.evaluate(
    () =>
      Array.from(document.querySelectorAll("button, a[href]")).filter(
        (el) =>
          (el.textContent ?? "").trim() === "" &&
          (el.getAttribute("aria-label") ?? "").trim() === "" &&
          (el.getAttribute("aria-labelledby") ?? "").trim() === "",
      ).length,
  );
  expect(unnamedActions, `${name}: every link and button has an accessible name`).toBe(0);

  const badTables = await page.evaluate(
    () =>
      Array.from(document.querySelectorAll("table")).filter((table) => {
        const headers = Array.from(table.querySelectorAll("th"));
        if (headers.length === 0) return true;
        return headers.some(
          (th) => th.getAttribute("scope") !== "col" && th.getAttribute("scope") !== "row",
        );
      }).length,
  );
  expect(badTables, `${name}: every data table uses scoped headers`).toBe(0);

  const currentNav = await page.locator('nav[aria-label="Primary"] [aria-current="page"]').count();
  expect(currentNav, `${name}: primary nav marks the current page`).toBeGreaterThanOrEqual(1);

  // Next.js mounts its own route announcer (role="alert") inside a
  // next-route-announcer shadow root on every navigation. That is framework
  // chrome, not page content, so the audit matches light DOM only. A page
  // alert that never clears still fails, but framework chrome does not flake.
  await expect
    .poll(async () => page.locator(":light([role='alert'])").count(), { timeout: 10000 })
    .toBe(0);
  const alertsOnLoad = await page.locator(":light([role='alert'])").count();
  const alertHtml =
    alertsOnLoad === 0
      ? ""
      : await page.evaluate(() =>
          Array.from(document.querySelectorAll('[role="alert"]'))
            .map((el) => el.outerHTML.slice(0, 400))
            .join("\n---\n"),
        );
  expect(
    alertsOnLoad,
    `${name}: no assertive live region fires on clean load. Found: ${alertHtml}`,
  ).toBe(0);
  const liveCount = await page.locator(":light([role='status']), :light([aria-live])").count();
  expect(liveCount, `${name}: polite live regions stay bounded (no spam)`).toBeLessThanOrEqual(
    maxLiveRegions,
  );

  const failures = await page.evaluate(() => {
    const failures: ControlFailure[] = [];
    const isVisible = (el: Element): boolean => {
      const rect = el.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    };
    const controls = Array.from(
      document.querySelectorAll(
        'button, a[href], select, textarea, input:not([type="checkbox"]):not([type="radio"]):not([type="hidden"])',
      ),
    );
    for (const el of controls) {
      if (!isVisible(el)) continue;
      const style = getComputedStyle(el);
      if (style.visibility === "hidden" || style.display === "none") continue;
      if (el.classList.contains("ledger-skip-link")) continue;
      // WCAG 2.5.8 inline exception: a link inside a sentence keeps the
      // surrounding text readable and is not a standalone touch target.
      if (el.tagName === "A" && style.display === "inline") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 44 || rect.height < 44) {
        const testId = el.getAttribute("data-testid") ?? "";
        const text = (el.textContent ?? "").trim().slice(0, 48);
        failures.push({
          kind: el.tagName.toLowerCase(),
          label: `${testId === "" ? "" : `#${testId} `}"${text}"`,
          width: Math.round(rect.width),
          height: Math.round(rect.height),
        });
      }
    }
    const grouped = Array.from(
      document.querySelectorAll('input[type="checkbox"], input[type="radio"]'),
    );
    for (const el of grouped) {
      if (!isVisible(el)) continue;
      const label = el.closest("label");
      const target = label ?? el;
      const rect = target.getBoundingClientRect();
      if (rect.width < 44 || rect.height < 44) {
        const testId = el.getAttribute("data-testid") ?? "";
        failures.push({
          kind: `grouped-${(el as HTMLInputElement).type}`,
          label: `#${testId}`,
          width: Math.round(rect.width),
          height: Math.round(rect.height),
        });
      }
    }
    return failures;
  });
  expect(failures, `${name}: touch targets measure at least 44x44`).toEqual([]);

  const seen = new Set<string>();
  const focusFailures: string[] = [];
  for (let step = 0; step < 25; step += 1) {
    await page.keyboard.press("Tab");
    const record = await page.evaluate(() => {
      const active = document.activeElement;
      if (!(active instanceof HTMLElement)) return null;
      const style = getComputedStyle(active);
      return {
        key: `${active.tagName}#${active.getAttribute("data-testid") ?? active.textContent?.trim().slice(0, 24) ?? ""}`,
        focusVisible: active.matches(":focus-visible"),
        outlineWidth: style.outlineWidth,
        outlineStyle: style.outlineStyle,
      };
    });
    if (record === null) continue;
    seen.add(record.key);
    if (record.focusVisible && (record.outlineWidth === "0px" || record.outlineStyle === "none")) {
      focusFailures.push(record.key);
    }
  }
  expect(
    seen.size,
    `${name}: keyboard reaches multiple stops without a trap`,
  ).toBeGreaterThanOrEqual(5);
  expect(focusFailures, `${name}: every keyboard focus stop shows a visible outline`).toEqual([]);

  await auditNoHorizontalOverflow(page, `${name} at 1280px`);
}

export async function auditZoomReflow(page: Page, name: string, screenshot: string): Promise<void> {
  const viewport = page.viewportSize();
  const width = viewport === null ? 640 : Math.max(360, Math.round(viewport.width / 2));
  const height = viewport?.height ?? 900;
  await page.setViewportSize({ width, height });
  await auditNoHorizontalOverflow(page, `${name} at 200% zoom equivalent`);
  await page.screenshot({ path: screenshot, fullPage: true });
  if (viewport !== null) await page.setViewportSize(viewport);
}

export async function auditReducedMotion(
  page: Page,
  name: string,
  screenshot: string,
): Promise<void> {
  await page.emulateMedia({ reducedMotion: "reduce" });
  const durations = await page.evaluate(() =>
    Array.from(
      document.querySelectorAll(
        ".ledger-search-button, .ledger-filter-chip, .ledger-notice-action",
      ),
    )
      .slice(0, 4)
      .map((el) => getComputedStyle(el).transitionDuration),
  );
  for (const duration of durations) {
    expect(duration, `${name}: reduced-motion collapses transitions`).toBe("0s");
  }
  await page.screenshot({ path: screenshot, fullPage: true });
  await page.emulateMedia({ reducedMotion: "no-preference" });
}

export { controlLabel };
