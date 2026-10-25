// Methodology diagrams: pure-data contracts plus static assertions that the
// server-rendered page module carries every required diagram label, testid,
// and preserved notice string. No browser, no build.

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_PRIORITY_FLOW,
  ORDERING_MODES,
  PIPELINE_FAILURE_BRANCH,
  PIPELINE_STAGES,
  SIGNAL_LANES,
  SIGNALS_CONVERGENCE,
} from "../src/components/methodology/diagram-data";

const PROJECT_ROOT = process.cwd();
const PAGE_SOURCE = readFileSync(path.join(PROJECT_ROOT, "app/methodology/page.tsx"), "utf8");
const PIPELINE_SOURCE = readFileSync(
  path.join(PROJECT_ROOT, "src/components/methodology/PipelineDiagram.tsx"),
  "utf8",
);
const ORDERING_SOURCE = readFileSync(
  path.join(PROJECT_ROOT, "src/components/methodology/OrderingDiagram.tsx"),
  "utf8",
);
const SIGNAL_SOURCE = readFileSync(
  path.join(PROJECT_ROOT, "src/components/methodology/SignalDiagram.tsx"),
  "utf8",
);
const RENDERED_SOURCES = [PAGE_SOURCE, PIPELINE_SOURCE, ORDERING_SOURCE, SIGNAL_SOURCE].join("\n");
const CSS_SOURCE = readFileSync(
  path.join(PROJECT_ROOT, "src/components/methodology/MethodologyDiagrams.module.css"),
  "utf8",
);

describe("pipeline diagram data", () => {
  it("numbers six stages in order with labeled handoffs", () => {
    expect(PIPELINE_STAGES).toHaveLength(6);
    PIPELINE_STAGES.forEach((stage, index) => {
      expect(stage.step).toBe(index + 1);
      expect(stage.title.length).toBeGreaterThan(0);
      expect(stage.detail.length).toBeGreaterThan(0);
    });
    expect(PIPELINE_STAGES[5]?.connectorLabel).toBeNull();
    for (const stage of PIPELINE_STAGES.slice(0, 5)) {
      expect(stage.connectorLabel?.length ?? 0).toBeGreaterThan(0);
    }
  });

  it("names the three free feeds and the four read models", () => {
    const first = `${PIPELINE_STAGES[0]?.title} ${PIPELINE_STAGES[0]?.detail}`;
    expect(first).toContain("CVE List V5");
    expect(first).toContain("CISA KEV");
    expect(first).toContain("FIRST EPSS");
    const last = PIPELINE_STAGES[5]?.detail ?? "";
    expect(last).toContain("read-only API");
    expect(last).toContain("Radar");
    expect(last).toContain("Replay");
  });

  it("keeps the failure branch: last-known-good, stale label, no frozen peers", () => {
    expect(PIPELINE_FAILURE_BRANCH).toContain("last-known-good");
    expect(PIPELINE_FAILURE_BRANCH).toContain("stale label");
    expect(PIPELINE_FAILURE_BRANCH).toContain("never freezes the others");
  });
});

describe("ordering diagram data", () => {
  it("encodes the six-key default priority flow in order", () => {
    expect(DEFAULT_PRIORITY_FLOW.map((step) => step.key)).toEqual([
      "KEV member before not listed",
      "EPSS present before unknown",
      "EPSS probability descending",
      "Known publication before unknown",
      "Publication descending",
      "CVE ID ASCII ascending",
    ]);
  });

  it("covers all four list modes with exact sort keys", () => {
    expect(ORDERING_MODES.map((mode) => mode.mode)).toEqual([
      "Known exploited",
      "Highest forecast",
      "New critical",
      "Rising forecast",
    ]);
    const byName = Object.fromEntries(ORDERING_MODES.map((mode) => [mode.mode, mode]));
    expect(byName["Known exploited"]?.sortKeys).toContain("KEV dateAdded descending");
    expect(byName["Highest forecast"]?.sortKeys).toContain("Raw EPSS probability descending");
    expect(byName["New critical"]?.eligibility).toContain("[T - 30d, T)");
    expect(byName["Rising forecast"]?.sortKeys).toContain("Delta percentage-points descending");
  });
});

describe("signal diagram data", () => {
  it("keeps three labeled lanes with distinct cautions", () => {
    expect(SIGNAL_LANES.map((lane) => lane.signal)).toEqual(["CVSS", "KEV", "EPSS"]);
    expect(SIGNAL_LANES[0]?.caution).toContain("not low");
    expect(SIGNAL_LANES[1]?.caution).toContain("not proof of safety");
    expect(SIGNAL_LANES[2]?.caution).toContain("never zero");
  });

  it("converges on kept-separate, never a computed score", () => {
    expect(SIGNALS_CONVERGENCE).toContain("never multiplied");
    expect(SIGNALS_CONVERGENCE).toContain("No composite score is computed");
  });
});

describe("methodology page carries the diagrams", () => {
  const requiredTestIds = [
    "methodology-anchor-nav",
    "methodology-pipeline",
    "methodology-pipeline-caption",
    "methodology-pipeline-failure",
    "methodology-ordering-flow",
    "methodology-ordering-modes",
    "methodology-signals-diagram",
    "methodology-signals-convergence",
    "methodology-generated-time",
  ];

  for (const testId of requiredTestIds) {
    it(`renders data-testid "${testId}"`, () => {
      expect(RENDERED_SOURCES).toContain(testId);
    });
  }

  it("keeps every pre-existing section and notice testid", () => {
    for (const testId of [
      "methodology-signals",
      "methodology-ordering-default",
      "methodology-ordering-known-exploited",
      "methodology-ordering-highest-forecast",
      "methodology-ordering-new-critical",
      "methodology-ordering-rising-forecast",
      "methodology-sources",
      "methodology-gaps",
      "methodology-checklist",
      "methodology-health",
      "notice-cve",
      "notice-kev",
      "notice-kev-marks",
      "notice-epss",
      "notice-epss-attribution",
      "notice-first-clarification",
      "notice-not-legal-advice",
      "notice-recheck",
    ]) {
      expect(PAGE_SOURCE).toContain(testId);
    }
  });

  it("anchors all seven nav targets to real section ids", () => {
    for (const id of [
      "methodology-section-signals",
      "methodology-section-pipeline",
      "methodology-section-ordering",
      "methodology-section-sources",
      "methodology-section-notices",
      "methodology-section-gaps",
      "methodology-section-status",
    ]) {
      expect(PAGE_SOURCE).toContain(`id="${id}"`);
      expect(PAGE_SOURCE).toContain(`href="#${id}"`);
    }
  });

  it("uses TimeText for the generated instant and HelpTip inside diagram headings", () => {
    expect(PAGE_SOURCE).toContain("<TimeText");
    expect(PAGE_SOURCE).toContain("<HelpTip");
  });

  it("keeps required notice phrases verbatim (whitespace-normalized like the e2e spec)", () => {
    const normalized = PAGE_SOURCE.replace(/\s+/g, " ");
    for (const phrase of [
      "reproduce MITRE",
      "no-charge reuse, not CC0",
      "Creative Commons 0 1.0",
      "nor implied endorsement",
      "free of charge, with no registration required",
      "never freezes the other",
      "never relabeled as current-day forecasts",
    ]) {
      expect(normalized).toContain(phrase);
    }
  });

  it("diagram styles use ledger tokens, never raw hex, with responsive and print rules", () => {
    expect(CSS_SOURCE).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(CSS_SOURCE).toContain("var(--ledger-");
    expect(CSS_SOURCE).toContain("@media (min-width: 900px)");
    expect(CSS_SOURCE).toContain("@media print");
    expect(CSS_SOURCE).toContain("prefers-reduced-motion");
  });
});
