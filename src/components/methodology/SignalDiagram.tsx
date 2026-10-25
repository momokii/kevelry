import { SIGNAL_LANES, SIGNALS_CONVERGENCE } from "./diagram-data";
import styles from "./MethodologyDiagrams.module.css";

// Signal-relationship diagram: three text-labeled lanes converging on the
// kept-separate verdict. Lane names are numbered text ("Lane 1"), never
// color alone.
export function SignalDiagram() {
  return (
    <figure className={styles.diagram} data-testid="methodology-signals-diagram">
      <figcaption
        className={styles.diagramCaption}
        data-testid="methodology-signals-diagram-caption"
      >
        Three signals, three lanes. Each lane names what the signal is and what it is not; they
        converge below on a single rule.
      </figcaption>
      <ul className={styles.laneList}>
        {SIGNAL_LANES.map((lane) => (
          <li key={lane.signal} className={styles.lane}>
            <span className={`ledger-label ${styles.laneName}`}>
              {lane.lane}: {lane.signal}
            </span>{" "}
            <span className="ledger-emphasis">{lane.meaning}</span>{" "}
            <span className="ledger-caveat">{lane.caution}</span>
          </li>
        ))}
      </ul>
      <div className={styles.convergence} data-testid="methodology-signals-convergence">
        <span className="ledger-label">Convergence </span>
        <span className="ledger-emphasis">{SIGNALS_CONVERGENCE}</span>
      </div>
    </figure>
  );
}
