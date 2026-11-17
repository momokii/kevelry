// Seeds the corpus the dev server under test reads, before any spec runs.
//
// The server is started with DATA_DIR=<repo>/.e2e/data, so this file — not the
// checkout's data/cve.db — is the one corpus the suite touches.
import { mkdirSync } from "node:fs";

import { E2E_DATA_DIR, resetToBaseline } from "./corpus";

export default function globalSetup(): void {
  mkdirSync(E2E_DATA_DIR, { recursive: true });
  resetToBaseline();
}
