import { PIPELINE_FAILURE_BRANCH, PIPELINE_STAGES } from "./diagram-data";
import styles from "./MethodologyDiagrams.module.css";

// Ingestion-to-publication pipeline as an ordered list styled into a
// diagram. Step order, titles, and connector labels are all real DOM text;
// the arrows are decorative CSS. Vertical below 900px, six lanes across on
// desktop. Renders on the server: no client JavaScript.
export function PipelineDiagram() {
  return (
    <figure className={styles.diagram} data-testid="methodology-pipeline">
      <figcaption className={styles.diagramCaption} data-testid="methodology-pipeline-caption">
        Ingestion pipeline: from free upstream feeds to the pages, API, Radar, and Replay. Read the
        numbered stages in order; each arrow names the handoff it draws.
      </figcaption>
      <ol className={`${styles.flowList} ${styles.flowListHorizontal}`}>
        {PIPELINE_STAGES.map((stage) => (
          <li key={stage.step}>
            <div className={styles.flowStep}>
              <span className="ledger-label">
                Step {stage.step} of {PIPELINE_STAGES.length}
              </span>{" "}
              <span className="ledger-emphasis">{stage.title}</span>
              <span className="ledger-caveat">{stage.detail}</span>
            </div>
            {stage.connectorLabel !== null ? (
              <div
                className={`${styles.flowConnector} ${styles.flowConnectorHorizontal}`}
                data-testid={`methodology-pipeline-connector-${stage.step}`}
              >
                {stage.connectorLabel}
              </div>
            ) : null}
          </li>
        ))}
      </ol>
      <div className={styles.failureBranch} data-testid="methodology-pipeline-failure">
        <span className="ledger-label">Failure branch </span>
        <span className="ledger-emphasis">{PIPELINE_FAILURE_BRANCH}</span>
      </div>
    </figure>
  );
}
