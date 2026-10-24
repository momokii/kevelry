import js from "@eslint/js";
import prettier from "eslint-config-prettier";

// NOTE: typescript-eslint is intentionally absent. Its 8.72.x peer range caps
// TypeScript at <6.1.0, so it cannot install alongside the pinned TypeScript
// 7.0.2 without --legacy-peer-deps. TypeScript files in this shell are covered
// by `npm run typecheck` (tsc --noEmit) and `npm run format:check` (prettier).
// Revisit once typescript-eslint publishes TypeScript 7 support.
export default [
  {
    ignores: [".next/**", "node_modules/**", "coverage/**", "playwright-report/**", "test-results/**"],
  },
  js.configs.recommended,
  prettier,
];
