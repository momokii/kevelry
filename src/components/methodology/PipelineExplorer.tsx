"use client";

import { useState } from "react";

import { PIPELINE_FAILURE_BRANCH, PIPELINE_STAGES } from "./diagram-data";

export function PipelineExplorer() {
  const [active, setActive] = useState(1);
  const stage = PIPELINE_STAGES.find((entry) => entry.step === active) ?? PIPELINE_STAGES[0];

  return (
    <figure className="pipeline-figure" data-testid="methodology-pipeline">
      <figcaption>
        Ingestion pipeline: from free upstream feeds to the pages, API, Radar, and Replay. Select a
        stage to see what it does and what it never does.
      </figcaption>
      <div className="pipeline-flow" role="group" aria-label="Pipeline stages">
        {PIPELINE_STAGES.map((entry, index) => (
          <div className="pipeline-step" key={entry.step}>
            <button
              type="button"
              className={`pipeline-node ${entry.step === active ? "is-active" : ""}`}
              aria-pressed={entry.step === active}
              data-testid={`methodology-pipeline-stage-${entry.step}`}
              onClick={() => setActive(entry.step)}
            >
              <span className="pipeline-number">{String(entry.step).padStart(2, "0")}</span>
              <span>{entry.title}</span>
            </button>
            {index < PIPELINE_STAGES.length - 1 ? (
              <span className="pipeline-arrow" aria-hidden="true">
                →
              </span>
            ) : null}
          </div>
        ))}
      </div>
      {stage !== undefined ? (
        <div className="pipeline-detail" aria-live="polite">
          <h3>
            {String(stage.step).padStart(2, "0")} · {stage.title}
          </h3>
          <p>{stage.detail}</p>
          {stage.connectorLabel !== null ? (
            <p className="chart-note">Handoff: {stage.connectorLabel}.</p>
          ) : (
            <p className="chart-note">Terminal stage: read models only, never upstream calls.</p>
          )}
        </div>
      ) : null}
      <p className="pipeline-failure" data-testid="methodology-pipeline-failure">
        <strong>Failure branch.</strong> {PIPELINE_FAILURE_BRANCH}
      </p>
    </figure>
  );
}
