// Clause 6 of the data-visibility standard: zero, missing, and unknown are three
// different things. The sparkline used to erase the whole figure as soon as one
// observation was missing (`values.some(v => v === null)` → `null`), so the
// observations that did exist disappeared too and nothing said why. These tests
// pin the honest version: the line breaks at the gap, the caption counts the
// absent observations, no point is plotted at zero for a missing date, and the
// figure still renders. The last case renders the component itself.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  EpssTrend,
  epssMissingCount,
  epssNearestObservedIndex,
  epssObservedIndices,
  epssTrendExtremes,
  epssTrendRuns,
  epssTrendValues,
  type EpssTrendPoint,
} from "../src/components/priority/PriorityView";

/** Four dated observations, the third one absent (stored value is not a number). */
const GAPPED: EpssTrendPoint[] = [
  { scoreDate: "2026-10-20", epss: "0.1", modelVersion: "v2026.06.15" },
  { scoreDate: "2026-10-21", epss: "0.2", modelVersion: "v2026.06.15" },
  { scoreDate: "2026-10-22", epss: "not-a-number", modelVersion: "v2026.06.15" },
  { scoreDate: "2026-10-23", epss: "0.4", modelVersion: "v2026.06.15" },
];

describe("epssTrendValues", () => {
  it("keeps a real zero and turns a non-value into null, never 0", () => {
    const values = epssTrendValues([
      { epss: "0" },
      { epss: "0.42" },
      { epss: "" },
      { epss: "   " },
      { epss: "n/a" },
      { epss: "1.4" },
      { epss: "-0.2" },
    ]);
    expect(values).toEqual([0, 0.42, null, null, null, 1, 0]);
  });
});

describe("epssTrendRuns", () => {
  it("returns one run per gap-free stretch so the line can break", () => {
    const values = epssTrendValues(GAPPED);
    const runs = epssTrendRuns(values);
    expect(runs.map((run) => [run.start, run.end])).toEqual([
      [0, 1],
      [3, 3],
    ]);
    // No coordinate is emitted for the missing date: nothing is plotted at zero.
    const missingX = (2 / (GAPPED.length - 1)) * 100;
    const plottedX = runs.flatMap((run) => run.coords.map((coord) => coord.x));
    expect(plottedX).not.toContain(missingX);
  });

  it("keeps an isolated observation as a run of one instead of bridging it", () => {
    const values = epssTrendValues([
      { epss: "0.3" },
      { epss: "n/a" },
      { epss: "0.5" },
      { epss: "n/a" },
      { epss: "0.7" },
    ]);
    const runs = epssTrendRuns(values);
    expect(runs.map((run) => run.coords.length)).toEqual([1, 1, 1]);
    expect(epssMissingCount(values)).toBe(2);
  });
});

describe("epssObservedIndices / epssMissingCount", () => {
  it("skips absent dates and counts them", () => {
    const values = epssTrendValues(GAPPED);
    expect(epssObservedIndices(values)).toEqual([0, 1, 3]);
    expect(epssMissingCount(values)).toBe(1);
    expect(epssMissingCount(epssTrendValues([{ epss: "0.1" }, { epss: "0.2" }]))).toBe(0);
  });
});

describe("epssNearestObservedIndex", () => {
  it("never lands on a missing date, even at its exact position", () => {
    const values = epssTrendValues(GAPPED);
    const missingFraction = 2 / (GAPPED.length - 1);
    const index = epssNearestObservedIndex(values, missingFraction);
    expect(index).not.toBeNull();
    expect(epssObservedIndices(values)).toContain(index);
    expect(index).not.toBe(2);
  });

  it("maps the plot edges and exact points to the observations there", () => {
    const values = epssTrendValues(GAPPED);
    expect(epssNearestObservedIndex(values, 0)).toBe(0);
    expect(epssNearestObservedIndex(values, 1)).toBe(3);
    expect(epssNearestObservedIndex(values, -5)).toBe(0);
  });

  it("returns null when nothing in the window has a value", () => {
    expect(epssNearestObservedIndex(epssTrendValues([{ epss: "n/a" }]), 0.5)).toBeNull();
  });
});

describe("epssTrendExtremes", () => {
  it("computes the window range from the observations that exist", () => {
    const extremes = epssTrendExtremes(epssTrendValues(GAPPED));
    expect(extremes.min).toEqual({ index: 0, value: 0.1 });
    expect(extremes.max).toEqual({ index: 3, value: 0.4 });
  });
});

describe("EpssTrend render", () => {
  it("still renders the figure with one missing observation and states the gap", () => {
    const markup = renderToStaticMarkup(createElement(EpssTrend, { points: GAPPED }));
    expect(markup).toContain('data-testid="priority-row-epss-trend"');
    // One polyline for the run before the gap, and the single isolated
    // observation after it is the latest marker: no line is drawn across the gap.
    expect(markup.match(/<polyline/g) ?? []).toHaveLength(1);
    expect(markup).toContain('data-testid="priority-row-epss-segment-0"');
    expect(markup).toContain('data-testid="priority-row-epss-latest"');
    // The caption names the absent observation…
    expect(markup).toContain("1 observation missing in the window");
    // …the strip says the keyboard and pointer skip that date…
    expect(markup).toContain("those dates are skipped by the pointer and the arrow keys");
    // …and the disclosure states absence in words rather than a zero.
    expect(markup).toContain("No observation");
    expect(markup).not.toContain("66.7,");
  });

  it("draws the observed stretches on either side of an interior gap", () => {
    const points: EpssTrendPoint[] = [
      { scoreDate: "2026-10-19", epss: "0.31", modelVersion: "v2026.06.15" },
      { scoreDate: "2026-10-20", epss: "0.35", modelVersion: "v2026.06.15" },
      { scoreDate: "2026-10-21", epss: "", modelVersion: "v2026.06.15" },
      { scoreDate: "2026-10-22", epss: "0.28", modelVersion: "v2026.06.15" },
      { scoreDate: "2026-10-23", epss: "0.3", modelVersion: "v2026.06.15" },
    ];
    const markup = renderToStaticMarkup(createElement(EpssTrend, { points }));
    // Two polylines: the line breaks at the missing date instead of interpolating.
    expect(markup.match(/<polyline/g) ?? []).toHaveLength(2);
    expect(markup).toContain('data-testid="priority-row-epss-segment-0"');
    expect(markup).toContain('data-testid="priority-row-epss-segment-3"');
    expect(markup).toContain("1 observation missing in the window");
  });

  it("says nothing about gaps when every observation is present", () => {
    const markup = renderToStaticMarkup(
      createElement(EpssTrend, {
        points: [
          { scoreDate: "2026-10-22", epss: "0.28", modelVersion: "v2026.06.15" },
          { scoreDate: "2026-10-23", epss: "0.3", modelVersion: "v2026.06.15" },
        ],
      } as { points: EpssTrendPoint[] }),
    );
    expect(markup.match(/<polyline/g) ?? []).toHaveLength(1);
    expect(markup).not.toContain("missing");
  });
});
