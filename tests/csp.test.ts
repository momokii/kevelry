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

  it("generates a distinct hex nonce per response", () => {
    const first = createCspNonce();
    const second = createCspNonce();
    expect(first).toMatch(/^[a-f0-9]{32}$/);
    expect(second).toMatch(/^[a-f0-9]{32}$/);
    expect(first).not.toBe(second);
  });
});
