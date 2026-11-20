// P1.2: one share formatter for one concept.
//
// Two helpers printed the same kind of number differently — the KEV rhythm's
// `shareOneDecimal` said `0.3%` where every other chart's `sharePercent` said
// `0.31%` — so the identical fact read two ways in two places. `/src/lib/share.ts`
// is now the only implementation, and the table below pins its rule at the
// boundaries where a wrong choice would misreport data: a small share must keep
// its second decimal, and a share just short of the whole must never round up to
// `100%`.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { sharePercent as chartSharePercent } from "../src/components/charts/chartTokens";
import { sharePercent } from "../src/lib/share";

/** Every source file the product renders from. */
function sourceFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(full));
      continue;
    }
    if (!/\.(ts|tsx|mjs|js)$/.test(entry.name)) continue;
    files.push(full);
  }
  return files;
}

describe("sharePercent", () => {
  it("prints a share of a denominator at the size-appropriate precision", () => {
    const cases: Array<[count: number, total: number, expected: string, why: string]> = [
      // Below 1%: two decimals. The second one is the only one that moves.
      [1, 322, "0.31%", "a small share keeps both decimals"],
      [3, 1000, "0.30%", "and stays at two decimals when it lands on a tenth"],
      [1, 100000, "<0.01%", "a non-zero share is never flattened to 0%"],
      [0, 322, "0%", "no count is a true zero"],
      // 1% and above: one decimal, with an exact .0 dropped.
      [1, 100, "1%", "the boundary is one decimal, not two"],
      [122, 1000, "12.2%", "one decimal above 1%"],
      [43, 322, "13.4%", "the KEV tooltip shares the donut's precision"],
      [12, 100, "12%", "an exact tenth is printed without the .0"],
      // Just short of the whole: never rounded up to a total it does not have.
      [999, 1000, "99.9%", "99.9% is not 100%"],
      [994, 1000, "99.4%", "and neither is 99.4% rounded down to the wrong tenth"],
      [100, 100, "100%", "the whole denominator is 100%"],
      // Degenerate inputs read as an honest zero rather than NaN or -0%.
      [0, 0, "0%", "no denominator"],
      [5, 0, "0%", "no denominator with a count"],
      [-3, 10, "0%", "a negative share cannot exist"],
      [Number.NaN, 10, "0%", "a non-finite share cannot exist"],
      [10, Number.POSITIVE_INFINITY, "0%", "a non-finite denominator"],
      // A count above its denominator is a data error, and it is shown as one
      // instead of being clamped into a plausible 100%.
      [322, 300, "107.3%", "an over-total share is reported, not hidden"],
    ];
    for (const [count, total, expected, why] of cases) {
      expect(sharePercent(count, total), `${count}/${total}: ${why}`).toBe(expected);
    }
  });

  it("is one function, not a copy per layer", () => {
    // The charts import it from `chartTokens`, which re-exports the lib module;
    // identity is the assertion that the two surfaces cannot drift apart.
    expect(chartSharePercent).toBe(sharePercent);
  });

  it("is the only place a percentage string is rounded", () => {
    // A share formatted by hand is a share that can disagree with every other
    // one: this is the exact bug P1.2 fixed (`0.3%` beside `0.31%`). Any
    // `toFixed(...)` glued to a `%` outside the one helper fails here.
    const offenders: string[] = [];
    for (const file of [...sourceFiles("src"), ...sourceFiles("app")]) {
      const relative = path.relative(process.cwd(), file).split(path.sep).join("/");
      if (relative === "src/lib/share.ts") continue;
      const text = readFileSync(file, "utf8");
      if (/toFixed\([^)]*\)\}%/.test(text)) offenders.push(relative);
    }
    expect(offenders).toEqual([]);
    expect(
      sourceFiles("src").some((file) => readFileSync(file, "utf8").includes("shareOneDecimal")),
    ).toBe(false);
  });
});
