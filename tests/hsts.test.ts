// HSTS is opt-in on purpose: the documented local path is plain-HTTP
// `http://localhost:3000`, and a browser that cached `Strict-Transport-Security`
// for that host would refuse the only URL the operator has. These tests pin the
// three ways the decision can go: an HTTPS request always gets the header, an
// explicit flag adds it to plain HTTP, and everything else (including a
// malformed flag) leaves it off.

import { describe, expect, it } from "vitest";

import {
  HSTS_HEADER_VALUE,
  HSTS_MAX_AGE_SECONDS,
  hstsEnabled,
  hstsHeaderValue,
  isHttpsRequest,
} from "../src/lib/hsts";

const httpRequest = (headers: Record<string, string> = {}): Request =>
  new Request("http://localhost:3000/priority", { headers });

describe("hstsEnabled", () => {
  it("is off by default and for a malformed value", () => {
    expect(hstsEnabled({})).toBe(false);
    expect(hstsEnabled({ HSTS_ENABLED: "" })).toBe(false);
    expect(hstsEnabled({ HSTS_ENABLED: "false" })).toBe(false);
    expect(hstsEnabled({ HSTS_ENABLED: "1" })).toBe(false);
    expect(hstsEnabled({ HSTS_ENABLED: "yes" })).toBe(false);
    expect(hstsEnabled({ HSTS_ENABLED: "TRUE!" })).toBe(false);
  });

  it("accepts true, trimmed and case-insensitive", () => {
    expect(hstsEnabled({ HSTS_ENABLED: "true" })).toBe(true);
    expect(hstsEnabled({ HSTS_ENABLED: "  TRUE  " })).toBe(true);
  });
});

describe("isHttpsRequest", () => {
  it("reads the URL scheme", () => {
    expect(isHttpsRequest(new Request("https://radar.test/api/v1/health"))).toBe(true);
    expect(isHttpsRequest(httpRequest())).toBe(false);
  });

  it("accepts a proxy-set X-Forwarded-Proto and ignores an unusable one", () => {
    expect(isHttpsRequest(httpRequest({ "x-forwarded-proto": "https" }))).toBe(true);
    expect(isHttpsRequest(httpRequest({ "x-forwarded-proto": " https " }))).toBe(true);
    expect(isHttpsRequest(httpRequest({ "x-forwarded-proto": "http, https" }))).toBe(false);
    expect(isHttpsRequest(httpRequest({ "x-forwarded-proto": "" }))).toBe(false);
    expect(isHttpsRequest(httpRequest({ "x-forwarded-proto": "gopher" }))).toBe(false);
  });
});

describe("hstsHeaderValue", () => {
  it("omits the header over plain HTTP without the flag", () => {
    expect(hstsHeaderValue(httpRequest(), {})).toBeNull();
  });

  it("sends the header when the request is already HTTPS", () => {
    const request = new Request("https://radar.test/api/v1/health");
    expect(hstsHeaderValue(request, {})).toBe(HSTS_HEADER_VALUE);
    expect(hstsHeaderValue(httpRequest({ "x-forwarded-proto": "https" }), {})).toBe(
      HSTS_HEADER_VALUE,
    );
  });

  it("sends the header over plain HTTP only with the explicit flag", () => {
    expect(hstsHeaderValue(httpRequest(), { HSTS_ENABLED: "true" })).toBe(HSTS_HEADER_VALUE);
    expect(hstsHeaderValue(httpRequest(), { HSTS_ENABLED: "on" })).toBeNull();
  });

  it("never scopes the header to subdomains this app cannot vouch for", () => {
    expect(HSTS_MAX_AGE_SECONDS).toBe(31_536_000);
    expect(HSTS_HEADER_VALUE).toBe("max-age=31536000");
    expect(HSTS_HEADER_VALUE).not.toContain("includeSubDomains");
  });
});
