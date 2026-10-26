"use client";

import { useState } from "react";

type Mode =
  "default-priority" | "known-exploited" | "highest-forecast" | "new-critical" | "rising-forecast";

const MODE_LABELS: Record<Mode, string> = {
  "default-priority": "Default priority",
  "known-exploited": "Known exploited",
  "highest-forecast": "Highest forecast",
  "new-critical": "New critical",
  "rising-forecast": "Rising forecast",
};

export function ScoringExample() {
  const [mode, setMode] = useState<Mode>("default-priority");
  const example = {
    id: "CVE-2099-0001",
    title: "Remote heap overflow in an edge gateway",
    kev: true,
    kevDate: "23 Oct 2026",
    epss: "72%",
    cvss: "9.8 v3.1",
    published: "20 Oct 2026",
    delta: "+8 pp since 16 Oct",
  };
  return (
    <div className="scoring-example" data-testid="methodology-scoring-example">
      <div className="scoring-tabs" role="tablist" aria-label="Priority mode">
        {(Object.keys(MODE_LABELS) as Mode[]).map((key) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={mode === key}
            className={`btn btn-sm ${mode === key ? "btn-primary" : "btn-ghost"}`}
            onClick={() => setMode(key)}
          >
            {MODE_LABELS[key]}
          </button>
        ))}
      </div>
      <div className="scoring-row">
        <span className="mono">{example.id}</span>
        <strong>{example.title}</strong>
        <span className="pill">KEV · {example.kevDate}</span>
        <span className="pill">EPSS {example.epss}</span>
        <span className="pill">CVSS {example.cvss}</span>
      </div>
      <ol className="scoring-keys">
        {mode === "default-priority" ? (
          <>
            <li className="is-winning">
              <strong>KEV member</strong>
              <span>First key: listed before not listed.</span>
            </li>
            <li>
              <strong>EPSS present</strong>
              <span>Scored before unknown.</span>
            </li>
            <li>
              <strong>EPSS descending</strong>
              <span>Raw probability, not percentile.</span>
            </li>
            <li>
              <strong>Publication known/descending</strong>
              <span>Known dates first, then newest.</span>
            </li>
            <li>
              <strong>CVE ID ascending</strong>
              <span>Final deterministic tie-break.</span>
            </li>
          </>
        ) : mode === "known-exploited" ? (
          <>
            <li className="is-winning">
              <strong>KEV dateAdded descending</strong>
              <span>The newest catalog addition comes first.</span>
            </li>
            <li>
              <strong>CVE ID ascending</strong>
              <span>Tie-break only.</span>
            </li>
          </>
        ) : mode === "highest-forecast" ? (
          <>
            <li className="is-winning">
              <strong>EPSS probability descending</strong>
              <span>Raw probability, not percentile.</span>
            </li>
            <li>
              <strong>Publication known/descending</strong>
              <span>Known dates first, then newest.</span>
            </li>
            <li>
              <strong>CVE ID ascending</strong>
              <span>Final tie-break.</span>
            </li>
          </>
        ) : mode === "new-critical" ? (
          <>
            <li className="is-winning">
              <strong>Modern CVSS ≥ 9.0 inside [T−30d, T)</strong>
              <span>ADP-only, legacy, and unscored are ineligible.</span>
            </li>
            <li>
              <strong>Publication descending</strong>
              <span>Newest eligible first.</span>
            </li>
            <li>
              <strong>CVE ID ascending</strong>
              <span>Final tie-break.</span>
            </li>
          </>
        ) : (
          <>
            <li className="is-winning">
              <strong>Positive same-model delta</strong>
              <span>{example.delta}; missing d or d−7 is ineligible.</span>
            </li>
            <li>
              <strong>Current probability descending</strong>
              <span>Used after delta.</span>
            </li>
            <li>
              <strong>CVE ID ascending</strong>
              <span>Final tie-break.</span>
            </li>
          </>
        )}
      </ol>
      <p className="chart-note">
        Illustrative values, not a live record. The highlighted key is the first one that explains
        this row’s position. No weighted sum, product, or composite score is computed.
      </p>
    </div>
  );
}
