import { defineConfig } from "@playwright/test";

/**
 * Two dev servers, one corpus.
 *
 * The assistant's feature gate is read from the environment at boot, so the two
 * page states a reader can meet — enabled with a composer, disabled with the
 * operator's variable — cannot exist in one process. `assistant.spec.ts` runs
 * against the enabled server; the disabled state is asserted against the second
 * one, which shares `.e2e/data` (read-only for that spec) and nothing else.
 *
 * The enabled server streams through the test-only fake transport
 * (`AI_FAKE_TRANSPORT=1`, refused under `APP_ENV=production`). `APP_ENV` is set
 * explicitly to `development` for two reasons: this checkout's `.env` says
 * `production` (and a fake provider must never activate under that marker), and
 * `APP_ENV` must be one of the three values `src/lib/config.ts` accepts —
 * `test` is not one of them.
 *
 * The assistant key goes in `env`, not in the command string: the value is a
 * placeholder, but a `KEY=value` literal in tracked source is exactly what a
 * secret-scanning gate flags, and this file should never look like it carries a
 * credential. Playwright merges `env` over `process.env` for the child.
 */
const SHARED_ENV =
  "DATA_DIR=./.e2e/data SCHEDULE_ENABLED=false INGEST_ON_START=false APP_ENV=development";

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
  webServer: [
    {
      // The suite owns .e2e/data. DATA_DIR never points at the checkout's data/,
      // which the deployed instance keeps open, so a spec that swaps its corpus
      // cannot disturb the running app and the running app cannot disturb the
      // suite. The ingestion worker is off: only a spec may change the corpus.
      //
      // The assistant is on, with a placeholder key and the offline transport, so
      // the desk streams a canned turn with no socket and no credential.
      command: `${SHARED_ENV} AI_ENABLED=true AI_FAKE_TRANSPORT=1 npm run dev -- --port 3210`,
      env: { AI_API_KEY: "e2e-placeholder-key" },
      url: "http://localhost:3210/showcase",
      // Never reuse: a dev server already on 3210 would serve the checkout's
      // data/ instead of the seeded .e2e corpus. The suite owns the port.
      reuseExistingServer: false,
      timeout: 120 * 1000,
    },
    {
      // The same app with the assistant switched off: the state a keyless
      // deployment renders. Its own build directory keeps the two compilers from
      // writing over each other.
      command: `${SHARED_ENV} AI_ENABLED=false NEXT_DIST_DIR=.next-ai-off npm run dev -- --port 3211`,
      url: "http://localhost:3211/assistant",
      reuseExistingServer: false,
      timeout: 120 * 1000,
    },
  ],
});
