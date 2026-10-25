import { DEFAULT_PRIORITY_FLOW, ORDERING_MODES } from "./diagram-data";
import styles from "./MethodologyDiagrams.module.css";

// Scoring/ordering diagram: the default-priority decision flow plus a
// compact comparison table of the four list modes. Sort keys mirror the
// exact ordering-rule prose; no composite score exists anywhere here.
export function OrderingDiagram() {
  return (
    <>
      <figure className={styles.diagram} data-testid="methodology-ordering-flow">
        <figcaption
          className={styles.diagramCaption}
          data-testid="methodology-ordering-flow-caption"
        >
          Default priority order. Compare these keys in order and stop at the first difference; the
          numbers carry the order, not color.
        </figcaption>
        <ol className={styles.decisionList}>
          {DEFAULT_PRIORITY_FLOW.map((step) => (
            <li key={step.position} className={styles.decisionStep}>
              <div className={styles.decisionBody}>
                <span className="ledger-emphasis">{step.key}</span>{" "}
                <span className="ledger-caveat">{step.detail}</span>
              </div>
            </li>
          ))}
        </ol>
      </figure>
      <figure className={styles.diagram} data-testid="methodology-ordering-modes">
        <figcaption
          className={styles.diagramCaption}
          data-testid="methodology-ordering-modes-caption"
        >
          The four priority lists side by side: who is eligible and which sort keys apply. KEV
          membership is a sort key only where listed; EPSS is a sort key only where listed.
        </figcaption>
        <div className={styles.tableScroll}>
          <table className={styles.modesTable}>
            <caption>
              Eligibility and exact sort keys per list mode. No composite score is computed.
            </caption>
            <thead>
              <tr>
                <th scope="col">List</th>
                <th scope="col">Eligibility</th>
                <th scope="col">Sort keys in order</th>
              </tr>
            </thead>
            <tbody>
              {ORDERING_MODES.map((mode) => (
                <tr
                  key={mode.mode}
                  data-testid={`methodology-ordering-mode-${mode.mode.toLowerCase().replace(/[^a-z]+/g, "-")}`}
                >
                  <th scope="row">
                    <span className="ledger-emphasis">{mode.mode}</span>
                  </th>
                  <td>{mode.eligibility}</td>
                  <td>
                    <ol>
                      {mode.sortKeys.map((key) => (
                        <li key={key}>{key}</li>
                      ))}
                    </ol>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </figure>
    </>
  );
}
