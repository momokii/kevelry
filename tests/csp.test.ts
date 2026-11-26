import { describe, expect, it } from "vitest";

import { buildContentSecurityPolicy, createCspNonce } from "../src/lib/csp";

describe("content security policy", () => {
  it("is nonce-only in production", () => {
    const policy = buildContentSecurityPolicy("abc123", { development: false });
    expect(policy).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    // No escape hatch for inline or eval script in the shipped policy.
    const scriptSrc = /script-src([^;]*)/.exec(policy)?.[1] ?? "";
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc).not.toContain("'unsafe-eval'");
    expect(policy).toContain("frame-ancestors 'none'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("base-uri 'self'");
    expect(policy).toContain("form-action 'self'");
    // Inline style attributes are how React writes chart geometry.
    expect(policy).toContain("style-src 'self' 'unsafe-inline'");
    expect(policy).toContain("default-src 'self'");
  });

  it("relaxes script-src only for the dev server", () => {
    const policy = buildContentSecurityPolicy("abc123", { development: true });
    expect(policy).toContain("'unsafe-eval'");
    expect(policy).toContain("'nonce-abc123'");
  });

  it("allows data: and blob: images and nothing wider", () => {
    const policy = buildContentSecurityPolicy("abc123", { development: false });
    const imgSrc = /img-src([^;]*)/.exec(policy)?.[1]?.trim() ?? "";
    // The exact list: the two schemes this app generates its own images with, and
    // its own origin. A thumbnail is a base64 `data:` URL; a downloaded brief is
    // read back through an object URL.
    expect(imgSrc).toBe("'self' data: blob:");
    // Nothing wider: no wildcard, no scheme-wide source, no remote host.
    expect(imgSrc).not.toContain("*");
    expect(imgSrc).not.toMatch(/https?:/);
    expect(policy).not.toContain("*");
    // `data:` is an image source only — never a script, a frame or a connection.
    expect(/script-src([^;]*)/.exec(policy)?.[1] ?? "").not.toContain("data:");
    expect(/connect-src([^;]*)/.exec(policy)?.[1] ?? "").not.toContain("data:");
  });

  it("generates a distinct hex nonce per response", () => {
    const first = createCspNonce();
    const second = createCspNonce();
    expect(first).toMatch(/^[a-f0-9]{32}$/);
    expect(second).toMatch(/^[a-f0-9]{32}$/);
    expect(first).not.toBe(second);
  });
});
