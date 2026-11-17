// The suite's corpus is disposable: drop .e2e/ when the run ends. Nothing
// outside .e2e/ is removed.
import { removeE2eRoot } from "./corpus";

export default function globalTeardown(): void {
  removeE2eRoot();
}
