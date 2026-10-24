import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SPEC_PATH = join(ROOT, "openapi", "v1.yaml");
const DOCS_DIR = join(ROOT, "docs", "api");

function readSpec(): string {
  return readFileSync(SPEC_PATH, "utf8");
}

function readDocs(): Map<string, string> {
  const files = readdirSync(DOCS_DIR).filter((name) => name.endsWith(".md")).sort();
  const pages = new Map<string, string>();
  for (const name of files) {
    pages.set(name, readFileSync(join(DOCS_DIR, name), "utf8"));
  }
  expect(pages.size).toBeGreaterThan(0);
  return pages;
}

/** `  /api/v1/...:` lines are path items (4-space indent marks operations). */
function specPaths(spec: string): string[] {
  return spec
    .split("\n")
    .map((line) => line.match(/^  (\/api\/v1[^:]*):\s*$/)?.[1])
    .filter((path): path is string => path !== undefined);
}

/** Lines shaped like `GET /api/v1/...` declare a documented endpoint. */
function documentedEndpoints(pages: Map<string, string>): { page: string; endpoint: string }[] {
  const found: { page: string; endpoint: string }[] = [];
  for (const [page, text] of pages) {
    for (const line of text.split("\n")) {
      const match = line.match(/^\s*GET\s+(\/api\/v1[^\s`?]*)/);
      if (match?.[1]) {
        found.push({ page, endpoint: match[1] });
      }
    }
  }
  return found;
}

function templateMatches(template: string, concrete: string): boolean {
  const pattern = new RegExp(
    `^${template.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\{[^/]+\\\}/g, "[^/]+")}$`,
  );
  return pattern.test(concrete.split("?")[0] ?? "");
}

describe("api contract completeness", () => {
  it("documents every spec path and every documented endpoint exists in the spec", () => {
    const templates = specPaths(readSpec());
    expect(templates.length).toBeGreaterThan(0);

    const documented = documentedEndpoints(readDocs());
    expect(documented.length).toBeGreaterThan(0);

    const missing = documented.filter(
      ({ endpoint }) => !templates.some((template) => templateMatches(template, endpoint)),
    );
    expect(
      missing.map(({ page, endpoint }) => `${page}: ${endpoint}`),
      "documented endpoints missing from openapi/v1.yaml",
    ).toEqual([]);

    const undocumented = templates.filter((template) =>
      documented.every(({ endpoint }) => !templateMatches(template, endpoint)),
    );
    expect(undocumented, "spec paths with no docs/api page").toEqual([]);
  });

  it("stays read-only: no write operations in the spec, none documented", () => {
    const spec = readSpec();
    const operations = spec
      .split("\n")
      .map((line) => line.match(/^    (get|post|put|patch|delete|options|head|trace):\s*$/)?.[1])
      .filter((op): op is string => op !== undefined);
    expect(operations.length).toBeGreaterThan(0);
    expect(operations, "spec must expose GET routes only").toEqual(
      operations.filter((op) => op === "get"),
    );

    for (const [page, text] of readDocs()) {
      for (const line of text.split("\n")) {
        expect(
          line.match(/^\s*(POST|PUT|PATCH|DELETE)\s+\/api\/v1/),
          `${page} must not document write endpoints`,
        ).toBeNull();
      }
    }
  });

  it("carries provenance in every path block", () => {
    const chunks = readSpec().split(/^\s{2}\/api\/v1/gm).slice(1);
    expect(chunks.length).toBeGreaterThan(0);
    for (const chunk of chunks) {
      expect(chunk.includes("provenance")).toBe(true);
    }
  });

  it("represents unknown EPSS as explicit null, never 0", () => {
    const spec = readSpec();
    expect(spec.match(/status: unknown\s*\n\s*value: null/), "unknown EPSS example").not.toBeNull();
    expect(spec.match(/status: known\s*\n\s*value: 0\b/), "known-zero EPSS example").not.toBeNull();
    const unknownBlocks = spec.match(/status: unknown\s*\n\s*value: [^\n]*/g) ?? [];
    expect(unknownBlocks.length).toBeGreaterThan(0);
    for (const block of unknownBlocks) {
      expect(block.endsWith("value: null")).toBe(true);
    }
  });
});
