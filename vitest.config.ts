import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // `.tsx` covers the DOM-level primitive tests (jsdom, opted in per file);
    // everything else keeps the node environment.
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
    setupFiles: ["./tests/setup.ts"],
  },
});
