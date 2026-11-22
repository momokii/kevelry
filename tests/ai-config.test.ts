import { describe, expect, it } from "vitest";

import {
  AI_BASE_URL_DEFAULT,
  AI_MAX_TOKENS_FLOOR,
  AiConfigError,
  aiEnabled,
  loadAiConfig,
} from "../src/lib/ai/config";

const KEY = "sentinel-key-do-not-log-9f3a";

describe("loadAiConfig", () => {
  it("defaults to disabled with the documented gateway and budget settings", () => {
    const config = loadAiConfig({});
    expect(config.enabled).toBe(false);
    expect(config.apiKey).toBeNull();
    expect(config.baseUrl).toBe(AI_BASE_URL_DEFAULT);
    expect(config.model).toBe("deepseek-v4.1-flash");
    expect(config.webFetchEnabled).toBe(false);
    expect(config.sessionBudgetTokens).toBe(60_000);
    expect(config.dailyBudgetUsd).toBe(5);
    expect(config.maxTurns).toBe(12);
    expect(config.maxInputChars).toBe(2000);
    expect(config.requestTimeoutMs).toBe(45_000);
    expect(config.streamIdleTimeoutMs).toBe(20_000);
    expect(AI_MAX_TOKENS_FLOOR).toBe(512);
  });

  it("keeps the key readable but out of JSON serialization", () => {
    const config = loadAiConfig({ AI_ENABLED: "true", AI_API_KEY: KEY });
    expect(config.apiKey).toBe(KEY);
    expect(JSON.stringify(config)).not.toContain(KEY);
    expect({ ...config }).not.toHaveProperty("apiKey");
  });

  it("treats a blank key as missing", () => {
    const config = loadAiConfig({ AI_ENABLED: "true", AI_API_KEY: "   " });
    expect(config.apiKey).toBeNull();
  });

  it("overrides the model and base url from the environment", () => {
    const config = loadAiConfig({
      AI_BASE_URL: "https://gateway.example.test/openai/v1/",
      AI_MODEL: "some-other-model",
    });
    expect(config.baseUrl).toBe("https://gateway.example.test/openai/v1");
    expect(config.model).toBe("some-other-model");
  });

  it("refuses a plain-http base url because the key travels in a bearer header", () => {
    expect(() =>
      loadAiConfig({ AI_BASE_URL: "http://opencode.ai/inference/go/openai/v1" }),
    ).toThrowError(AiConfigError);
  });

  it("refuses a malformed token budget instead of silently defaulting", () => {
    expect(() => loadAiConfig({ AI_SESSION_BUDGET_TOKENS: "lots" })).toThrowError(
      /AI_SESSION_BUDGET_TOKENS/,
    );
  });

  it("refuses a non-positive daily budget", () => {
    expect(() => loadAiConfig({ AI_DAILY_BUDGET_USD: "0" })).toThrowError(/AI_DAILY_BUDGET_USD/);
    expect(() => loadAiConfig({ AI_DAILY_BUDGET_USD: "-1" })).toThrowError(/AI_DAILY_BUDGET_USD/);
  });

  it("refuses a non-boolean enable flag", () => {
    expect(() => loadAiConfig({ AI_ENABLED: "yes" })).toThrowError(/AI_ENABLED/);
  });

  it("refuses an unknown non-boolean web-fetch flag", () => {
    expect(() => loadAiConfig({ AI_WEB_FETCH_ENABLED: "on" })).toThrowError(/AI_WEB_FETCH_ENABLED/);
  });
});

describe("aiEnabled", () => {
  it("stays off when AI_ENABLED is absent even with a key present", () => {
    expect(aiEnabled({ AI_API_KEY: KEY })).toEqual({ enabled: false, disabled: "off" });
  });

  it("reports no-key when enabled without a key", () => {
    expect(aiEnabled({ AI_ENABLED: "true" })).toEqual({ enabled: false, disabled: "no-key" });
  });

  it("enables only when the flag and a key are both present", () => {
    expect(aiEnabled({ AI_ENABLED: "true", AI_API_KEY: KEY })).toEqual({
      enabled: true,
      disabled: null,
    });
  });

  it("reports over-budget from the storage probe, and skips the probe when keyless", () => {
    let probes = 0;
    const dailyBudgetExceeded = (): boolean => {
      probes += 1;
      return true;
    };
    expect(aiEnabled({ AI_ENABLED: "true" }, { dailyBudgetExceeded })).toEqual({
      enabled: false,
      disabled: "no-key",
    });
    expect(probes).toBe(0);
    expect(aiEnabled({ AI_ENABLED: "true", AI_API_KEY: KEY }, { dailyBudgetExceeded })).toEqual({
      enabled: false,
      disabled: "over-budget",
    });
    expect(probes).toBe(1);
  });

  it("fails closed to over-budget when the ledger probe throws", () => {
    expect(
      aiEnabled(
        { AI_ENABLED: "true", AI_API_KEY: KEY },
        {
          dailyBudgetExceeded: () => {
            throw new Error("database unavailable");
          },
        },
      ),
    ).toEqual({ enabled: false, disabled: "over-budget" });
  });
});
