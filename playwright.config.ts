import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  workers: 1,
  reporter: "list",
  globalSetup: "./tests/e2e/global-setup.ts",
  globalTeardown: "./tests/e2e/global-teardown.ts",
  use: {
    baseURL: "http://localhost:3210",
  },
  timeout: 60 * 1000,
  webServer: {
    // The suite owns .e2e/data. DATA_DIR never points at the checkout's data/,
    // which the deployed instance keeps open, so a spec that swaps its corpus
    // cannot disturb the running app and the running app cannot disturb the
    // suite. The ingestion worker is off: only a spec may change the corpus.
    command:
      "DATA_DIR=./.e2e/data SCHEDULE_ENABLED=false INGEST_ON_START=false npm run dev -- --port 3210",
    url: "http://localhost:3210/showcase",
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
});
