import { describe, expect, it } from "vitest";

import { loadConfig } from "../src/lib/config";

const VALID_ENV = {
  APP_ENV: "development",
  PORT: "3000",
  DATA_DIR: "./data",
  SCHEDULE_ENABLED: "false",
} as const;

describe("loadConfig", () => {
  it("loads a valid shell config", () => {
    const config = loadConfig({ ...VALID_ENV });
    expect(config).toEqual({
      appEnv: "development",
      port: 3000,
      dataDir: "./data",
      scheduleEnabled: false,
    });
  });

  it("loads the seeded test env from the real runtime env", () => {
    const config = loadConfig();
    expect(config).toEqual({
      appEnv: "development",
      port: 3000,
      dataDir: "./data",
      scheduleEnabled: false,
    });
  });

  it("fails closed against the real runtime env when DATA_DIR is explicitly deleted", () => {
    const saved = process.env.DATA_DIR;
    delete process.env.DATA_DIR;
    try {
      expect(() => loadConfig()).toThrowError(/DATA_DIR/);
    } finally {
      if (saved !== undefined) {
        process.env.DATA_DIR = saved;
      }
    }
  });

  it("fails closed when APP_ENV is missing", () => {
    const { APP_ENV: _removed, ...rest } = VALID_ENV;
    expect(() => loadConfig({ ...rest })).toThrowError(/APP_ENV/);
  });

  it("fails closed when DATA_DIR is missing", () => {
    const { DATA_DIR: _removed, ...rest } = VALID_ENV;
    expect(() => loadConfig({ ...rest })).toThrowError(/DATA_DIR/);
  });

  it("fails closed when PORT is missing", () => {
    const { PORT: _removed, ...rest } = VALID_ENV;
    expect(() => loadConfig({ ...rest })).toThrowError(/PORT/);
  });

  it("fails closed when SCHEDULE_ENABLED is missing", () => {
    const { SCHEDULE_ENABLED: _removed, ...rest } = VALID_ENV;
    expect(() => loadConfig({ ...rest })).toThrowError(/SCHEDULE_ENABLED/);
  });

  it("rejects an unknown APP_ENV instead of defaulting silently", () => {
    expect(() => loadConfig({ ...VALID_ENV, APP_ENV: "test" })).toThrowError(/APP_ENV/);
  });
});
