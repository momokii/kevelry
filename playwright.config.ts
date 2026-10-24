import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://localhost:3210",
  },
  timeout: 60 * 1000,
  webServer: {
    command: "npm run dev -- --port 3210",
    url: "http://localhost:3210/showcase",
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
});
