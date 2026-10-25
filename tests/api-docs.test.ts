// No-drift test for the browsable API docs (task 45). The page must list
// exactly the path+method pairs documented in openapi/v1.yaml — no invented
// endpoints, none missing — and every endpoint needs a copy-paste example.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  buildCurl,
  DEPRECATION_TEXT,
  endpointSlug,
  ERROR_CATALOG,
  FRESHNESS_TEXT,
  PAGINATION_TEXT,
  parseSpec,
  RATE_LIMIT_TEXT,
} from "../app/api-docs/spec";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SPEC = readFileSync(join(ROOT, "openapi", "v1.yaml"), "utf8");
const HUMAN_DOCS = readFileSync(join(ROOT, "docs", "api", "README.md"), "utf8");

/** `  /api/v1/...:` lines are path items, same extraction as api-contract. */
function specPaths(spec: string): string[] {
  return spec
    .split("\n")
    .map((line) => line.match(/^  (\/api\/v1[^:]*):\s*$/)?.[1])
    .filter((path): path is string => path !== undefined);
}

function specMethods(spec: string): string[] {
  return spec
    .split("\n")
    .map((line) => line.match(/^    (get|post|put|patch|delete|options|head|trace):\s*$/)?.[1])
    .filter((op): op is string => op !== undefined);
}

describe("api-docs endpoint list", () => {
  it("equals the parsed OpenAPI paths/methods exactly (no drift)", () => {
    const { endpoints } = parseSpec(SPEC);
    const paths = specPaths(SPEC);
    const methods = specMethods(SPEC);

    expect(endpoints.length).toBe(paths.length);
    expect(endpoints.length).toBe(methods.length);

    const rendered = new Set(endpoints.map((endpoint) => `${endpoint.method} ${endpoint.path}`));
    for (let i = 0; i < paths.length; i += 1) {
      const expected = `${(methods[i] ?? "").toUpperCase()} ${paths[i]}`;
      expect(rendered.has(expected), `missing endpoint: ${expected}`).toBe(true);
    }
    expect(rendered.size).toBe(paths.length);
  });

  it("gives every endpoint a summary, responses, and a curl example", () => {
    const { endpoints } = parseSpec(SPEC);
    expect(endpoints.length).toBeGreaterThan(0);
    for (const endpoint of endpoints) {
      expect(endpoint.summary, `${endpoint.operationId} summary`).not.toBe("");
      expect(endpoint.responses.length, `${endpoint.operationId} responses`).toBeGreaterThan(0);
      const curl = buildCurl("https://radar.example.org", endpoint);
      expect(
        curl.startsWith('curl "https://radar.example.org/api/v1/'),
        `${endpoint.operationId} curl`,
      ).toBe(true);
      expect(endpointSlug(endpoint).length, `${endpoint.operationId} slug`).toBeGreaterThan(0);
    }
  });

  it("keeps prose sections anchored in docs/api/README.md", () => {
    const plainDocs = HUMAN_DOCS.replace(/`/g, "").replace(/\s+/g, " ").toLowerCase();
    const anchored = (line: string, label: string) => {
      const phrase = line.slice(0, 24).replace(/`/g, "").replace(/\s+/g, " ").toLowerCase();
      expect(plainDocs.includes(phrase), `${label} drift: ${phrase}`).toBe(true);
    };
    for (const line of RATE_LIMIT_TEXT) anchored(line, "rate limit");
    for (const line of PAGINATION_TEXT) anchored(line, "pagination");
    for (const line of FRESHNESS_TEXT) anchored(line, "freshness");
    for (const line of DEPRECATION_TEXT) anchored(line, "deprecation");
    for (const row of ERROR_CATALOG) {
      expect(HUMAN_DOCS.includes(row.code), `error catalog drift: ${row.code}`).toBe(true);
    }
  });
});
