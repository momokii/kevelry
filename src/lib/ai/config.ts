// Fail-closed configuration for the AI assistant.
//
// The feature has no half-on state: it runs only when `AI_ENABLED=true` AND an
// API key is present. Every other combination is reported as a typed reason
// (`off`, `no-key`, `over-budget`) instead of throwing into a page render, so
// the UI can say "disabled" honestly rather than rendering a broken composer.
//
// Validation is strict for supplied values: a malformed budget, turn cap or
// timeout is a configuration bug, and silently falling back to a default would
// make the budget a lie. Missing values are different — they take the documented
// default.
//
// The API key is held in a non-enumerable property: `config.apiKey` works for
// the client, while `JSON.stringify(config)` and object spreads cannot carry it
// into a log line or an error payload by accident.

/** Gateway base URL from the credential research; overridable per deployment. */
export const AI_BASE_URL_DEFAULT = "https://opencode.ai/inference/go/openai/v1";

/** The one model id verified against the gateway. */
export const AI_MODEL_DEFAULT = "deepseek-v4.1-flash";

/**
 * Reasoning models spend completion tokens thinking before they emit anything.
 * Probes at 8–512 tokens returned empty tool arguments or empty content with
 * `finish_reason: "length"`; 512 was the first budget that produced complete
 * output. This is a correctness floor, not a tuning knob.
 */
export const AI_MAX_TOKENS_FLOOR = 512;

/** Budget for a turn that cites records, matching the plan's default. */
export const AI_MAX_TOKENS_DEFAULT = 1024;

export type AiDisabledReason = "off" | "no-key" | "over-budget" | "invalid-config";

export interface AiConfig {
  readonly enabled: boolean;
  /** Server-only. Non-enumerable at runtime; never serialized. */
  readonly apiKey: string | null;
  readonly baseUrl: string;
  readonly model: string;
  readonly webFetchEnabled: boolean;
  readonly sessionBudgetTokens: number;
  readonly dailyBudgetUsd: number;
  readonly maxTurns: number;
  readonly maxInputChars: number;
  readonly requestTimeoutMs: number;
}

export interface AiGate {
  readonly enabled: boolean;
  /** `null` exactly when enabled; otherwise why the feature is unavailable. */
  readonly disabled: AiDisabledReason | null;
}

export interface AiGateOptions {
  /**
   * Ledger probe, injected so this module stays free of storage imports. The
   * route passes `() => ledger.dailyBudgetExceeded()`; a keyless instance never
   * calls it.
   */
  readonly dailyBudgetExceeded?: () => boolean;
}

/** A supplied AI setting is malformed; absent settings take their default. */
export class AiConfigError extends Error {
  readonly name = "AiConfigError";
}

type Env = Record<string, string | undefined>;

function readEnv(env: Env, name: string): string | null {
  const raw = env[name];
  if (raw === undefined) return null;
  const trimmed = raw.trim();
  return trimmed === "" ? null : trimmed;
}

function parseBoolean(env: Env, name: string, fallback: boolean): boolean {
  const raw = readEnv(env, name);
  if (raw === null) return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new AiConfigError(`${name} must be "true" or "false" (got ${JSON.stringify(raw)}).`);
}

function parseInteger(env: Env, name: string, fallback: number, min: number): number {
  const raw = readEnv(env, name);
  if (raw === null) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min) {
    throw new AiConfigError(`${name} must be an integer >= ${min} (got ${JSON.stringify(raw)}).`);
  }
  return value;
}

function parseUsd(env: Env, name: string, fallback: number): number {
  const raw = readEnv(env, name);
  if (raw === null) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new AiConfigError(
      `${name} must be a positive dollar amount (got ${JSON.stringify(raw)}).`,
    );
  }
  return value;
}

function parseBaseUrl(env: Env): string {
  const raw = readEnv(env, "AI_BASE_URL");
  if (raw === null) return AI_BASE_URL_DEFAULT;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AiConfigError("AI_BASE_URL must be an absolute https URL.");
  }
  if (parsed.protocol !== "https:") {
    throw new AiConfigError("AI_BASE_URL must use https; the API key travels in a bearer header.");
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new AiConfigError("AI_BASE_URL must not embed credentials.");
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    throw new AiConfigError("AI_BASE_URL must not carry a query string or fragment.");
  }
  return parsed.toString().replace(/\/+$/, "");
}

/** Parses the AI environment. Throws `AiConfigError` for a malformed supplied value. */
export function loadAiConfig(env: Env = process.env): AiConfig {
  const apiKey = readEnv(env, "AI_API_KEY");
  const config: AiConfig = {
    enabled: parseBoolean(env, "AI_ENABLED", false),
    apiKey: null,
    baseUrl: parseBaseUrl(env),
    model: readEnv(env, "AI_MODEL") ?? AI_MODEL_DEFAULT,
    webFetchEnabled: parseBoolean(env, "AI_WEB_FETCH_ENABLED", false),
    sessionBudgetTokens: parseInteger(env, "AI_SESSION_BUDGET_TOKENS", 60_000, 1),
    dailyBudgetUsd: parseUsd(env, "AI_DAILY_BUDGET_USD", 5),
    maxTurns: parseInteger(env, "AI_MAX_TURNS", 12, 1),
    maxInputChars: parseInteger(env, "AI_MAX_INPUT_CHARS", 2000, 1),
    // The gateway is a reasoning model behind a remote proxy: a turn that
    // cannot answer in 45 s is a failure the UI should name, not a hang.
    requestTimeoutMs: parseInteger(env, "AI_REQUEST_TIMEOUT_MS", 45_000, 1000),
  };
  Object.defineProperty(config, "apiKey", {
    value: apiKey,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return config;
}

/**
 * The gate for an already-parsed config: explicitly enabled, a key present,
 * and the ledger reporting headroom. Precedence matters — `off` before
 * `no-key`, so flipping the flag is the operator's first signal.
 */
export function aiGate(config: AiConfig, options: AiGateOptions = {}): AiGate {
  if (!config.enabled) return { enabled: false, disabled: "off" };
  if (config.apiKey === null) return { enabled: false, disabled: "no-key" };
  if (options.dailyBudgetExceeded !== undefined) {
    let exhausted: boolean;
    try {
      exhausted = options.dailyBudgetExceeded();
    } catch {
      // An unreadable ledger is not proof of headroom. Fail closed to the
      // nearest honest state the UI already knows how to render.
      return { enabled: false, disabled: "over-budget" };
    }
    if (exhausted) return { enabled: false, disabled: "over-budget" };
  }
  return { enabled: true, disabled: null };
}

/** Loads the AI environment and returns the gate. Never returns the key. */
export function aiEnabled(env: Env = process.env, options: AiGateOptions = {}): AiGate {
  return aiGate(loadAiConfig(env), options);
}
